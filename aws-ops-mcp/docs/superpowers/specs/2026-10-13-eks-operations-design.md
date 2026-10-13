# EKS operations 0.6.0 — approved design and execution

Approved intent: withdrawal blockers, network dependencies, health comparisons, Spot resilience and historical rightsizing. Keep deterministic read-only collection separate from developer changes.

Architecture: reuse safe Kubernetes normalization/SSM profiles for withdrawal and resilience; bounded process-local health baselines; targeted SDK tools for SG dependency and CloudWatch time-window queries. Avoid adding network/CloudWatch scans to every EKS investigation. Preserve existing tools and evidence budgets.

Acceptance: explicit unknowns for incomplete data, no drain authorization, no SG mutation or tuning; PDB selector/volume/taint/request correctness; no cross-account history; no false deltas on recreated pods; paginated sparse metrics never zero; bounded envelopes; tests of AWS SDK inputs, protocol schema and isolated wheel. Fixtures synthetic, no client credentials/data in Git.

Execution: normalization, pure readiness/history analyzers, two targeted tools, documentation and examples, offline suite, isolated MCP package smoke, review, conventional commit and normal push. Client reload/live acceptance remain separate. No subagents or infrastructure changes.
