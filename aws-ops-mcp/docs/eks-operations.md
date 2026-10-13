# EKS 0.6.0: withdrawal, resilience, health history, dependencies and rightsizing

## Scope approved

Conservative read-only evolution on top of 0.5.0. The user approved all five fronts and publication. Existing full/nodes/workloads/migration profiles remain available. No drain, SG mutation, GitOps sync or automatic resource tuning.

## Withdrawal and Spot resilience

`full` and `migration` emit:

- `withdrawal_summary`: complete coverage/gaps, remaining non-DaemonSet On-Demand workloads, blocked count. `drain_authorized=false` always.
- `withdrawal_workload`: controller resolved through ReplicaSets; singleton/unmanaged/local-storage risks; matching PDBs and disruption budget/status; PVC/PV topology; node selector, required node affinity and NoSchedule/NoExecute tolerations; individual fit against current Spot node request headroom.
- `spot_resilience_summary` and `spot_workload_risk`: Spot concentration by pool/AZ, singleton replicas, colocation, missing AZ and name-based management-component indicators.

This is not full scheduler simulation: joint packing, extended resources, preferred affinity, pod affinity/spread, future provisioning, CSI attach limits and scheduling plugins are not proven. Missing/omitted constraints remain gaps. Requests for each pod cannot independently reserve the same free capacity. No automatic declaration that withdrawing a node is safe. Replica/AZ risk is observed placement, not fault-injection proof.

Empty policy/v1 PDB selectors match all namespace pods; null selectors match none. Unknown/custom label selectors are omitted and marked unknown. ReplicaSet ownership and safe PVC node affinity are now collected. Read-only RBAC example includes replicasets; no permission is applied by the MCP.

## Health snapshot history

Complete nodes/pods/Warning-event snapshots are compared by configured account alias, region and cluster, in process memory for up to24h. Maximum20 baselines and5MB, with250KB per snapshot. History does not survive MCP restart and is not a complete incident timeline. Incomplete/cancelled snapshots do not replace a baseline.

`health_comparison` reports same-UID restart increases, changed container waiting/termination state, timestamp-confirmed new OOM terminations, added/removed/not-ready nodes and new/updated Warning observations. First observation is not a claim that the failure is new. Recreated pods, missing termination timestamps and counter resets are not treated as same-container deltas. Output lists are bounded with truncation flags; no secrets, logs or annotations are stored.

## Targeted network dependency tool

`eks_network_dependency(account, region, source_security_group_ids, destination_kind, destination_name, source_private_ip="")`.

- destination_kind: redis (cache cluster ID, not replication group/serverless ID) or opensearch (domain name).
- Read the destination's attached SGs and its VPC; Redis uses the actual endpoint port, OpenSearch uses443.
- Evaluate TCP ingress via SG references/CIDRs, broad or SG-reference egress, and report exact proposed ingress scope without applying it.
- Optional source IPv4 checks ENI association and CIDR match. Caller-supplied SGs without an IP are unverified origins. Prefix-delegated pod IPs may not resolve by exact ENI-IP filter; no-match is not proof that the pod has no SG.
- Specific destination-CIDR egress cannot be resolved without destination IP; mark unknown. Cross-VPC routing, prefix-list expansion, NACL, NetworkPolicy, TLS/auth/domain policies and functional probes are outside scope.

A rule observed is not a connection proven. Multiple destination SGs contribute ingress as a union. Each supplied source SG is assessed separately; if a real source ENI has multiple SGs, egress union requires additional interpretation.

## Historical rightsizing tool

`eks_rightsizing(account, region, cluster, namespace, pod_name, hours=168, cpu_request="", memory_request="")`.

Queries only ContainerInsights pod_cpu_usage_total (millicores) and pod_memory_working_set (bytes), using exact ClusterName/Namespace/PodName dimensions and Maximum per3600s bucket. Window24–336h,10 pages maximum,336 buckets per metric; timestamp deduplication and partial-status validation. Call budget45s plus one bounded in-flight request.

Returns mean, maximum and p95 of hourly maxima, coverage and missing-data status. This is not raw-sample p95. PodName can aggregate multiple replicas; FullPodName/OTel schemas are not queried. Missing series are not zero.

Optional current request references are Kubernetes quantities and MUST match the same aggregation as the queried series. With API-complete data and>=80% hour coverage, a candidate request equal to observed maximum plus30% is emitted for review. It is not a per-container/per-replica recommendation or a safe reduction proof. Configuration changes/rollouts and startup peaks during uncovered periods are not reconstructed. No limit/request is changed.

## Permissions and evidence

IAM example adds optional ec2:DescribeNetworkInterfaces, elasticache:DescribeCacheClusters/DescribeCacheSubnetGroups, es:DescribeDomain and cloudwatch:GetMetricData. Existing DescribeSecurityGroups access is reused. Authenticated account/region and output budgets are preserved. Read-only examples are not applied automatically.

New tools return bounded envelopes and detailed evidence IDs. A deny, pagination cycle, deadline, no data or partial metric response stays an explicit gap. An installed MCP process remains on its pinned commit until updated/reloaded. Local/offline verification is not live acceptance.

## Sources

- https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Container-Insights-reference-performance-entries-EKS.html
- https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/container-insights-eks-classic-metrics.html
- https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_GetMetricData.html
