# Execution Tool Validation Phase 3

## Executive Summary and decision

**INSUFFICIENT_REAL_RUNS.** The purpose-specific primitive is implemented and locally verified, but zero complete genuine Codex baseline/treatment pairs are present. No simulated, deterministic, or Phase 2 synthesized trace is counted.

## Primitive and boundary

`verify_change` reads the current Git working-tree diff and executes at most four repository-configured checks in fixed class order. The caller can provide only configured check identifiers and an optional repository-relative scope. It cannot write source files, repair failures, invoke a model, or retry a check.

The repository configuration is [`verify_change.yaml`](../verify_change.yaml). Each check is a configured executable plus exact argv. The implementation resolves the executable once, then executes it through the existing `ShellTool` with `ArgumentPolicy::Exact` and a `Sandbox`-validated working directory. Output diagnostics are capped at 2 KiB per check, with a hash of the complete captured output.

## Tool surface and experiment status

The treatment MCP adapter exposes exactly one tool, with the neutral description required by the protocol. The baseline adapter remains separate and does not expose `verify_change`. The harness has not invoked the primitive on an agent’s behalf.

One neutral treatment rollout was started in a fresh detached worktree at the frozen revision, with the prompt not mentioning `verify_change`; it is not a completed pair and is excluded from results. The selected task IDs and pre-recorded order are in `phase3-real-pairs.json`.

## Measurements and gate

All primary and secondary metrics, including independent adoption and verification coordination turns, are `null` because there are no complete genuine pairs. Real token fields are not estimated. The only valid decision is **INSUFFICIENT_REAL_RUNS**.

## Exactly one recommended next step

Run the remaining six or more complete fresh-worktree baseline/treatment pairs with the adapter binary fixed, archive each source rollout and independent manifest verification result, then regenerate this comparison from those artifacts.

## Confirmation

No generic workflow infrastructure, planner, retries, repair loop, persistence layer, queue, or cloud component was added.
