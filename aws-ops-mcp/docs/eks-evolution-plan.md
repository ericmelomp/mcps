# Implementation plan — EKS evolution 0.5.0

Approved scope: docs/superpowers/specs/2026-10-13-eks-ops-evolution-design.md.

Completed: allowlisted evidence normalization; effective requests and capacity/migration projection; fixed collection profiles; optional Argo CRDs; ELB service/endpoint context; bounded same-UID restart comparison; synthetic regression tests and MCP protocol schema checks.

Release gates: full offline suite, package build, isolated wheel MCP stdio, diff/secret review, normal commit/push. Installed client pin and live feature acceptance are separate from GitHub publication. No AWS remediation or real-client fixture data.
