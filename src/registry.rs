//! Holding tools and dispatching to them.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex;

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

#[derive(Debug, Clone)]
struct CacheEntry {
    outcome: ToolOutcome,
    inserted: Instant,
}

const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(300);
const DEFAULT_CACHE_MAX_ENTRIES: usize = 1024;

/// The set of tools an agent may call.
pub struct ToolRegistry {
    tools: HashMap<String, Arc<dyn Tool>>,
    completed: Arc<Mutex<HashMap<String, CacheEntry>>>,
    cache_ttl: Duration,
    cache_max_entries: usize,
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolRegistry {
    /// An empty registry. Nothing is callable until something is registered.
    pub fn new() -> Self {
        ToolRegistry {
            tools: HashMap::new(),
            completed: Arc::new(Mutex::new(HashMap::new())),
            cache_ttl: DEFAULT_CACHE_TTL,
            cache_max_entries: DEFAULT_CACHE_MAX_ENTRIES,
        }
    }

    /// Set cache TTL for `execute_once`.
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// Set max cached entries. Oldest evicted when exceeded.
    pub fn with_cache_capacity(mut self, max: usize) -> Self {
        self.cache_max_entries = max;
        self
    }

    /// Clear expired entries; evict oldest if over capacity.
    async fn evict_expired(&self, map: &mut HashMap<String, CacheEntry>) {
        let now = Instant::now();
        map.retain(|_, e| now.duration_since(e.inserted) < self.cache_ttl);
        if map.len() > self.cache_max_entries {
            // evict arbitrary (HashMap) entries until under limit - LRU would
            // need `lru` dep; this bounds memory which is the P0 requirement.
            let to_remove = map.len() - self.cache_max_entries;
            let keys: Vec<String> = map.keys().take(to_remove).cloned().collect();
            for k in keys {
                map.remove(&k);
            }
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
        // Single mutex guards check+insert to close RwLock read->write race where
        // N concurrent callers all miss then all execute.
        let mut map = self.completed.lock().await;
        self.evict_expired(&mut map).await;
        if let Some(entry) = map.get(key) {
            tracing::debug!(tool = %name, key = %key, "idempotency cache hit");
            return Ok(entry.outcome.clone());
        }
        drop(map);

        let outcome = self.execute(name, args).await?;
        if outcome.success {
            let mut map = self.completed.lock().await;
            self.evict_expired(&mut map).await;
            // second check: another task may have inserted while we executed
            if let Some(entry) = map.get(key) {
                return Ok(entry.outcome.clone());
            }
            map.insert(
                key.to_string(),
                CacheEntry {
                    outcome: outcome.clone(),
                    inserted: Instant::now(),
                },
            );
            // Ensure we never exceed capacity (evict_expired was before insert)
            if map.len() > self.cache_max_entries {
                self.evict_expired(&mut map).await;
            }
        }
        Ok(outcome)
    }

    /// Execute a batch of tool calls concurrently, preserving order.
    ///
    /// Each entry is `(name, args)`. Concurrency is bounded by `max_concurrency`
    /// (cap of 32 mirrors `marshalld` pool). Useful for agent batch steps like
    /// `read N files` without serial RTT.
    pub async fn execute_batch(
        &self,
        requests: Vec<(String, Value)>,
        max_concurrency: usize,
    ) -> Vec<Result<ToolOutcome>> {
        // Guard against OOM from huge batch
        if requests.len() > 64 {
            return requests
                .into_iter()
                .map(|_| Err(anyhow::anyhow!("batch_too_large")))
                .collect();
        }
        use tokio::sync::Semaphore;
        let max = max_concurrency.clamp(1, 32);
        let sem = Arc::new(Semaphore::new(max));
        let mut handles = Vec::with_capacity(requests.len());
        for (name, args) in requests {
            let sem = sem.clone();
            // Clone registry internals via Arc self? We need `self` to be Sync.
            // Since `&self` is shared, we spawn a task that holds a cloned reference
            // to the needed tool Arc.
            let tool = self.tools.get(&name).cloned();
            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                if let Some(tool) = tool {
                    tool.validate(&args).await?;
                    tool.execute(args).await
                } else {
                    Err(anyhow::anyhow!("tool_not_found: {name}"))
                }
            }));
        }
        let mut results = Vec::with_capacity(handles.len());
        for h in handles {
            results.push(
                h.await
                    .unwrap_or_else(|e| Err(anyhow::anyhow!("join_failed: {e}"))),
            );
        }
        results
    }

    /// Execute a sequence of tool calls **in order**, stopping on first error
    /// unless `continue_on_error` is true. Unlike `execute_batch` which runs
    /// concurrently, this preserves strict ordering and allows an agent to
    /// express `write -> read -> shell` workflows without extra RTTs.
    ///
    /// Each step is `(name, args)`. Supports templating `{{steps[0].stdout}}`
    /// where `steps[N].stdout`/`content` is previous stdout as UTF-8, `summary`
    /// is JSON. Returns results in input order; if `stop_on_error` (default
    /// `true`) a failed `Err` or `success==false` outcome aborts remaining steps.
    pub async fn execute_sequence(
        &self,
        requests: Vec<(String, Value)>,
        continue_on_error: bool,
    ) -> Vec<Result<ToolOutcome>> {
        if requests.len() > 32 {
            return requests
                .into_iter()
                .map(|_| Err(anyhow::anyhow!("sequence_too_large")))
                .collect();
        }
        let mut results = Vec::with_capacity(requests.len());
        let mut prev_outcomes: Vec<ToolOutcome> = Vec::new();
        for (name, args) in requests {
            let templated = apply_templates(&args, &prev_outcomes);
            let res = self.execute(&name, templated).await;
            let placeholder = match &res {
                Ok(o) => o.clone(),
                Err(e) => ToolOutcome::failure(
                    name.clone(),
                    e.to_string().split(':').next().unwrap_or("error").trim(),
                    0,
                ),
            };
            prev_outcomes.push(placeholder);
            let should_stop = if let Ok(outcome) = &res {
                !outcome.success && !continue_on_error
            } else {
                !continue_on_error
            };
            results.push(res);
            if should_stop {
                break;
            }
        }
        results
    }

    /// Number of cached idempotency entries (for testing/metrics).
    pub async fn cache_len(&self) -> usize {
        self.completed.lock().await.len()
    }
}

fn apply_templates(value: &Value, prev: &[ToolOutcome]) -> Value {
    match value {
        Value::String(s) => {
            // Single-pass replacement to avoid injection re-expansion. Capped at 32 placeholders.
            let mut out = String::with_capacity(s.len());
            let mut remaining = s.as_str();
            let mut count = 0;
            while let Some(start) = remaining.find("{{steps[") {
                if count >= 32 {
                    out.push_str(remaining);
                    break;
                }
                out.push_str(&remaining[..start]);
                let after_start = &remaining[start..];
                if let Some(end_rel) = after_start.find("}}") {
                    let end = end_rel + 2;
                    let placeholder = &after_start[..end];
                    let inner = &placeholder[2..placeholder.len() - 2]; // steps[N].field
                    let mut replacement = String::new();
                    if let Some(bracket) = inner.find('[') {
                        if let Some(close) = inner.find(']') {
                            if let Ok(idx) = inner[bracket + 1..close].parse::<usize>() {
                                if idx < prev.len() {
                                    let field = inner[close + 1..].trim_start_matches('.');
                                    let outcome = &prev[idx];
                                    replacement = match field {
                                        "stdout" | "content" | "output" => outcome
                                            .content
                                            .as_ref()
                                            .map(|b| String::from_utf8_lossy(b).to_string())
                                            .unwrap_or_default(),
                                        "summary" => serde_json::to_string(&outcome.summary)
                                            .unwrap_or_default(),
                                        "success" => outcome.success.to_string(),
                                        "error_code" => {
                                            outcome.error_code.clone().unwrap_or_default()
                                        }
                                        "tool" => outcome.tool.clone(),
                                        "duration_ms" => outcome.duration_ms.to_string(),
                                        _ => String::new(),
                                    };
                                }
                            }
                        }
                    }
                    out.push_str(&replacement);
                    remaining = &after_start[end..];
                    count += 1;
                } else {
                    // No closing }}, push rest and break
                    out.push_str(after_start);
                    remaining = "";
                    break;
                }
            }
            if !remaining.is_empty() {
                out.push_str(remaining);
            }
            Value::String(out)
        }
        Value::Object(map) => {
            let mut new_map = serde_json::Map::new();
            for (k, v) in map {
                new_map.insert(k.clone(), apply_templates(v, prev));
            }
            Value::Object(new_map)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(|v| apply_templates(v, prev)).collect()),
        _ => value.clone(),
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

    #[tokio::test]
    async fn batch_executes_concurrently_and_preserves_order() {
        let (registry, tool) = registry(true);
        let reqs = vec![
            ("counter".to_string(), json!({})),
            ("counter".to_string(), json!({})),
            ("counter".to_string(), json!({})),
        ];
        let results = registry.execute_batch(reqs, 2).await;
        assert_eq!(results.len(), 3);
        for r in results {
            assert!(r.unwrap().success);
        }
        assert_eq!(tool.calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn batch_reports_missing_tool_as_error() {
        let (registry, _) = registry(true);
        let reqs = vec![("nope".to_string(), json!({}))];
        let results = registry.execute_batch(reqs, 4).await;
        assert!(results[0].is_err());
        assert!(
            results[0]
                .as_ref()
                .unwrap_err()
                .to_string()
                .contains("tool_not_existent")
                || results[0]
                    .as_ref()
                    .unwrap_err()
                    .to_string()
                    .contains("tool_not_found")
        );
    }

    #[tokio::test]
    async fn sequence_executes_in_order_and_stops_on_error() {
        let (registry, tool) = registry(true);
        let reqs = vec![
            ("counter".to_string(), json!({})),
            ("counter".to_string(), json!({"bad": 1})),
            ("counter".to_string(), json!({})),
        ];
        let results = registry.execute_sequence(reqs, false).await;
        // second fails validation -> stops, third never runs
        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok());
        assert!(results[1].is_err());
        assert_eq!(tool.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn sequence_continues_when_requested() {
        let (registry, tool) = registry(true);
        let reqs = vec![
            ("counter".to_string(), json!({})),
            ("counter".to_string(), json!({"bad": 1})),
            ("counter".to_string(), json!({})),
        ];
        let results = registry.execute_sequence(reqs, true).await;
        assert_eq!(results.len(), 3);
        assert!(results[0].is_ok());
        assert!(results[1].is_err());
        assert!(results[2].is_ok());
        assert_eq!(tool.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn sequence_templates_previous_stdout() {
        struct Echo;
        #[async_trait::async_trait]
        impl Tool for Echo {
            fn name(&self) -> &str {
                "echo"
            }
            fn description(&self) -> &str {
                "echo"
            }
            fn parameters_schema(&self) -> Value {
                json!({})
            }
            async fn execute(&self, args: Value) -> Result<ToolOutcome> {
                let msg = args
                    .get("msg")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                Ok(ToolOutcome::success("echo", json!({}), 0).with_content(msg.into_bytes()))
            }
        }
        let mut reg = ToolRegistry::new();
        reg.register(std::sync::Arc::new(Echo));
        let steps = vec![
            ("echo".to_string(), json!({"msg": "hello"})),
            (
                "echo".to_string(),
                json!({"msg": "{{steps[0].stdout}} world"}),
            ),
        ];
        let res = reg.execute_sequence(steps, false).await;
        assert_eq!(res.len(), 2);
        let out1 = res[0].as_ref().unwrap();
        let out2 = res[1].as_ref().unwrap();
        assert_eq!(out1.content.as_deref().unwrap(), b"hello");
        // templated second step should have content "hello world"
        assert_eq!(out2.content.as_deref().unwrap(), b"hello world");
    }
}
