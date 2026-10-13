# EKS: migration, capacity and focused collection (0.5.0)

`eks_investigate(account, region, clusters, profile="full")` preserves the full investigation and supports fixed optional profiles:

| Profile | Collection |
|---|---|
| full | Existing AWS discovery, Kubernetes, dependencies and ELBv2, plus optional Argo CRDs |
| nodes | Cluster metadata, CRDs, nodes, Karpenter resources, node metrics and EC2 capacity lookup |
| workloads | Cluster metadata, nodes, pods, controllers, Warning events and optional Argo CRDs |
| migration | Workloads plus Services/EndpointSlices, volumes/PVCs, PDBs, Karpenter and node metrics |

Focused profiles skip unrelated IAM/network discovery and ELBv2. Excluded kinds are listed explicitly in profile evidence, not treated as observed healthy resources. Missing permissions still produce partial coverage. These profiles execute the same bounded SSM recipes, never arbitrary shell or changes to Kubernetes.

## Results

`eks_investigation_get` includes a compact migration summary when available, including while the job is still running (`provisional=true`). Full paginated evidence remains immutable and available after completion. Progress never proves completed coverage.

Evidence kinds:

- `migration_summary`: placement by pool/capacity/tier, remaining On-Demand/unknown pods, unscheduled pods and largest memory requests. Summary lists are bounded and mark truncation; use detailed evidence for all rows.
- `remaining_workload`: pod, node, owners, PVC names and allowlisted scheduling constraints. DaemonSet and StatefulSet counts are separate. Unknown capacity is explicit, not inferred from names.
- `node_capacity`: allocatable CPU/bytes, effective requests, request headroom, DaemonSet requests, instantaneous metrics and metrics timestamp. Missing metrics are null; incomplete pod coverage or unsupported pod-level resources makes requests/headroom null. Init containers, native sidecar init requests and pod overhead are accounted for. This is not scheduler simulation and does not validate all constraints/extended resources.
- `nodepools`: safe limits, replicas and selected requirements. Unknown/custom scheduling keys are omitted with an explicit constraint gap.
- `applications`: only ArgoCD sync/health/reconciliation status; no sources, Helm values, manifests, tokens or credentials.
- `rollouts`: phase, desired/ready/updated replicas, generations and safe conditions. An operator absent from complete CRD discovery is not applicable; access denied is partial.

Capacity labels are cross-checked against EC2 lifecycle where available. Disagreement is unknown. EC2 identity uses node provider IDs, never guesses based on pool names.

## Alert context

ELBv2 unhealthy findings retain the real state and include matched Service, endpoint coverage/count and same-name zero-replica workload candidates. Same-name is context, not proof of a selector relationship or intention to leave a workload stopped.

Container restart counts are cumulative, with the last termination timestamp where present. Complete pod snapshots for the same account/region/cluster can be compared in memory for 15 minutes. Deltas compare the same pod UID/container only; recreated pods and counter resets are separate. Baselines are bounded, never persisted, and partial snapshots do not replace them.

## Permissions and limits

The RBAC example includes optional get/list for `argoproj.io` applications/rollouts. The MCP does not apply RBAC/IAM changes. Existing EC2 DescribeInstances permission supports the capacity lookup. Profiles do not bypass identity validation, account isolation, timeouts, pagination or evidence budgets.

Migration summaries always report `withdrawal_assessment=not_assessed`. No drain approval, active probes, GitOps sync operations or business transaction tests. Pods/controllers healthy are operational evidence, not functional acceptance.

## Example

```json
{"account":"example","region":"us-east-1","clusters":["demo"],"profile":"migration"}
```

Publish, pin the installed client and validate it separately. Building/testing the local wheel does not update an already running MCP process.
