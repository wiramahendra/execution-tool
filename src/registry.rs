//! Holding tools and dispatching to them.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::RwLock;

use crate::{Tool, ToolOutcome};

/// A tool described for a planner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    /// Invocation name.
    pub name: String,
    /// One-line description.
    pub description: String,
    /// JSON Schema for arguments.
    pub parameters: Value,
}

impl ToolDefinition {
    /// Describe a tool.
    pub fn from_tool(tool: &dyn Tool) -> Self {
        ToolDefinition {
            name: tool.name().to_string(),
            description: tool.description().to_string(),
            parameters: tool.parameters_schema(),
        }
    }
}

/// The set of tools an agent may call.
#[derive(Default)]
pub struct ToolRegistry {
    tools: HashMap<String, Arc<dyn Tool>>,
    completed: Arc<RwLock<HashMap<String, ToolOutcome>>>,
}

impl ToolRegistry {
    /// An empty registry. Nothing is callable until something is registered.
    pub fn new() -> Self {
        ToolRegistry {
            tools: HashMap::new(),
            completed: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a tool, replacing any tool of the same name.
    pub fn register(&mut self, tool: Arc<dyn Tool>) {
        self.tools.insert(tool.name().to_string(), tool);
    }

    /// Every registered tool, described for a planner, sorted by name.
    pub fn definitions(&self) -> Vec<ToolDefinition> {
        let mut defs: Vec<ToolDefinition> = self
            .tools
            .values()
            .map(|t| ToolDefinition::from_tool(t.as_ref()))
            .collect();
        defs.sort_by(|a, b| a.name.cmp(&b.name));
        defs
    }

    /// Whether a tool is registered.
    pub fn has_tool(&self, name: &str) -> bool {
        self.tools.contains_key(name)
    }

    /// Registered tool names, sorted.
    pub fn tool_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.tools.keys().cloned().collect();
        names.sort();
        names
    }

    /// Number of registered tools.
    pub fn len(&self) -> usize {
        self.tools.len()
    }

    /// Whether nothing is registered.
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    /// Validate and run a tool.
    pub async fn execute(&self, name: &str, args: Value) -> Result<ToolOutcome> {
        let tool = self
            .tools
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("tool_not_found: {name}"))?;

        // Validate here as well as inside the tool: a tool may be called
        // directly, and policy must hold on both paths.
        tool.validate(&args).await?;

        let outcome = tool.execute(args).await;
        match &outcome {
            Ok(o) => tracing::info!(
                tool = %name, success = o.success, duration_ms = o.duration_ms, "tool executed"
            ),
            Err(e) => tracing::warn!(tool = %name, error = %e, "tool rejected"),
        }
        outcome
    }

    /// Run a tool once per `key`, returning the cached outcome on repeat calls.
    ///
    /// For retrying a step whose tool has a side effect. The cache is in-memory
    /// and per-process: it does not survive a restart, so it protects against a
    /// retried step, not against a crashed one.
    ///
    /// Only successful calls are cached. A failure that is cached would make a
    /// transient outage permanent for the lifetime of the process.
    pub async fn execute_once(&self, key: &str, name: &str, args: Value) -> Result<ToolOutcome> {
        if let Some(cached) = self.completed.read().await.get(key) {
            tracing::debug!(tool = %name, key = %key, "idempotency cache hit");
            return Ok(cached.clone());
        }

        let outcome = self.execute(name, args).await?;
        if outcome.success {
            self.completed
                .write()
                .await
                .insert(key.to_string(), outcome.clone());
        }
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Counter {
        calls: AtomicUsize,
        succeed: bool,
    }

    #[async_trait::async_trait]
    impl Tool for Counter {
        fn name(&self) -> &str {
            "counter"
        }
        fn description(&self) -> &str {
            "counts calls"
        }
        fn parameters_schema(&self) -> Value {
            json!({"type": "object"})
        }
        async fn validate(&self, args: &Value) -> Result<()> {
            if args.get("bad").is_some() {
                anyhow::bail!("rejected_by_policy");
            }
            Ok(())
        }
        async fn execute(&self, _args: Value) -> Result<ToolOutcome> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(if self.succeed {
                ToolOutcome::success("counter", json!({ "calls": n }), 0)
            } else {
                ToolOutcome::failure("counter", "always_fails", 0)
            })
        }
    }

    fn registry(succeed: bool) -> (ToolRegistry, Arc<Counter>) {
        let tool = Arc::new(Counter {
            calls: AtomicUsize::new(0),
            succeed,
        });
        let mut registry = ToolRegistry::new();
        registry.register(tool.clone());
        (registry, tool)
    }

    #[tokio::test]
    async fn an_unknown_tool_is_an_error() {
        let (registry, _) = registry(true);
        let err = registry.execute("nope", json!({})).await.unwrap_err();
        assert!(err.to_string().contains("tool_not_found"));
    }

    #[tokio::test]
    async fn the_registry_enforces_validation() {
        // Not just the tool: a tool reached through the registry must get the
        // same policy check as one called directly.
        let (registry, tool) = registry(true);
        assert!(registry
            .execute("counter", json!({"bad": 1}))
            .await
            .is_err());
        assert_eq!(
            tool.calls.load(Ordering::SeqCst),
            0,
            "policy ran after execute"
        );
    }

    #[tokio::test]
    async fn execute_once_runs_a_tool_only_once() {
        let (registry, tool) = registry(true);
        for _ in 0..5 {
            registry
                .execute_once("k1", "counter", json!({}))
                .await
                .unwrap();
        }
        assert_eq!(tool.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn different_keys_run_separately() {
        let (registry, tool) = registry(true);
        registry
            .execute_once("a", "counter", json!({}))
            .await
            .unwrap();
        registry
            .execute_once("b", "counter", json!({}))
            .await
            .unwrap();
        assert_eq!(tool.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn failures_are_not_cached() {
        // Caching a failure turns a transient outage into a permanent one.
        let (registry, tool) = registry(false);
        for _ in 0..3 {
            let outcome = registry
                .execute_once("k", "counter", json!({}))
                .await
                .unwrap();
            assert!(!outcome.success);
        }
        assert_eq!(tool.calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn definitions_and_names_are_sorted() {
        let mut registry = ToolRegistry::new();
        registry.register(Arc::new(Counter {
            calls: AtomicUsize::new(0),
            succeed: true,
        }));
        assert_eq!(registry.tool_names(), vec!["counter"]);
        assert_eq!(registry.definitions()[0].name, "counter");
        assert_eq!(registry.len(), 1);
    }

    #[tokio::test]
    async fn an_empty_registry_offers_nothing() {
        let registry = ToolRegistry::new();
        assert!(registry.is_empty());
        assert!(registry.definitions().is_empty());
        assert!(!registry.has_tool("anything"));
    }
}
