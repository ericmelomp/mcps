# Network troubleshooting implementation

Authorized scope: implement, test and push network improvements.

Delivered: IPv4 ENI path inspection and explicit CloudWatch VPC Flow Logs lookup, reusing authenticated aliases, bounded responses and evidence cache. Fixed read-only operations; no probes or AWS resource creation. Route ambiguity, unknown return ports, intermediate hops and TGW gaps remain explicit.

Acceptance: deterministic rules and incomplete cases, account isolation, SDK parameter validation, MCP stdio, isolated wheel smoke, build, pip check and diff review. Normal publication to origin/main after gates. Installed client configuration and live AWS acceptance are separate.
