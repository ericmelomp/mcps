"""AWS resource discovery and Kubernetes orchestration for one explicit cluster."""

from .eks_cli import CollectionError
from .eks_kubernetes import COMPONENTS, OPTIONAL, PATHS, OPTIONAL_CRDS, correlate
from .eks_insights import summarize
from .eks_ssm import resolve_bastion, run_recipe, validate_bastion


def pick(value, fields):
    return {key: value[key] for key in fields.split() if key in value}


PROFILES = {
    "nodes": ("customresourcedefinitions", "nodes", "nodepools", "nodeclaims", "ec2nodeclasses", "node_metrics"),
    "workloads": ("customresourcedefinitions", "nodes", "pods", "deployments", "statefulsets", "daemonsets", "events", "applications", "rollouts"),
    "migration": ("customresourcedefinitions", "nodes", "pods", "deployments", "statefulsets", "daemonsets", "events", "services", "endpointslices", "persistentvolumeclaims", "persistentvolumes", "poddisruptionbudgets", "nodepools", "nodeclaims", "ec2nodeclasses", "node_metrics", "applications", "rollouts"),
}

class Collector:
    def __init__(self, cli, account, cluster, emit):
        self.cli, self.account, self.cluster, self.emit = cli, account, cluster, emit
        self.items, self.findings, self.coverage = [], [], {}
        self.cluster_data = None
        self.profile = "full"

    def record(self, component, items, findings=(), complete=True, code=None, **extra):
        items = [{"cluster": self.cluster, "component": component, **item} for item in items]
        findings = [{"cluster": self.cluster, "component": component, **item} for item in findings]
        coverage = {"complete": complete, "observed": len(items), "finding_count": len(findings), **extra}
        if code:
            coverage["error"] = code
        self.items.extend(items)
        self.findings.extend(findings)
        self.coverage[component] = coverage
        self.emit({"kind": "component", "cluster": self.cluster, "component": component,
                   "items": items, "findings": findings, "coverage": coverage})

    def attempt(self, component, action):
        self.cli.check()
        try:
            return action()
        except CollectionError as exc:
            if exc.code in {"cancelled", "deadline_exceeded", "ssm_submission_unconfirmed"}:
                raise
            previous = self.coverage.get(component, {})
            self.record(component, [], complete=False, code=exc.code, observed=previous.get("observed", 0))
        except (KeyError, ValueError, TypeError):
            self.record(component, [], complete=False, code="aws_response_invalid")
        return None

    def listing(self, component, service, operation, key, parameters=None,
                fields=None, token="nextToken", output_token=None):
        def project(rows):
            if key == "Reservations":
                return [{"Instances": [pick(instance, "InstanceId State InstanceType PrivateIpAddress SubnetId VpcId SecurityGroups IamInstanceProfile Placement InstanceLifecycle SpotInstanceRequestId")
                                        for instance in row.get("Instances", [])]} for row in rows]
            return [pick(row, fields) if fields else row for row in rows]
        rows = []
        try:
            for page in self.cli.pages(service, operation, key, parameters, token, output_token):
                rows.extend(page)
                if len(rows) > 1000:
                    rows = rows[:1000]
                    raise CollectionError("resource_limit")
        except CollectionError as exc:
            projected = project(rows)
            self.record(component, [{"kind": component, "data": row} for row in projected], complete=False, code=exc.code)
            if exc.code in {"cancelled", "deadline_exceeded"}:
                raise
            return rows
        projected = project(rows)
        self.record(component, [{"kind": component, "data": row} for row in projected])
        return rows

    def aws(self):
        def cluster():
            data = self.cli.call("eks", "describe-cluster", {"name": self.cluster})["cluster"]
            self.cluster_data = data
            fields = "name arn status version platformVersion roleArn resourcesVpcConfig kubernetesNetworkConfig logging accessConfig computeConfig storageConfig upgradePolicy health"
            issues = self.aws_findings("cluster", data, {"ACTIVE"})
            self.record("aws.cluster", [{"kind": "cluster", "data": pick(data, fields)}], issues)
        self.attempt("aws.cluster", cluster)
        if not self.cluster_data:
            self.record("kubernetes", [], complete=False, code="cluster_description_unavailable")
            return
        data = self.cluster_data
        groups = self.listing("aws.nodegroups", "eks", "list-nodegroups", "nodegroups", {"clusterName": self.cluster})
        addons = self.listing("aws.addons", "eks", "list-addons", "addons", {"clusterName": self.cluster})
        profiles = self.listing("aws.fargate", "eks", "list-fargate-profiles", "fargateProfileNames", {"clusterName": self.cluster})
        roles, asgs = {data.get("roleArn")}, set()
        for name in groups:
            def nodegroup(name=name):
                row = self.cli.call("eks", "describe-nodegroup", {"clusterName": self.cluster, "nodegroupName": name})["nodegroup"]
                roles.add(row.get("nodeRole"))
                asgs.update(g["name"] for g in row.get("resources", {}).get("autoScalingGroups", []))
                self.record("aws.nodegroup." + name, [{"kind": "nodegroup", "data": pick(row,
                    "nodegroupName status version releaseVersion capacityType scalingConfig instanceTypes subnets nodeRole health resources updateConfig launchTemplate")}],
                    self.aws_findings(name, row, {"ACTIVE"}))
            self.attempt("aws.nodegroup." + name, nodegroup)
        for name in addons:
            def addon(name=name):
                row = self.cli.call("eks", "describe-addon", {"clusterName": self.cluster, "addonName": name})["addon"]
                roles.add(row.get("serviceAccountRoleArn"))
                self.record("aws.addon." + name, [{"kind": "addon", "data": pick(row,
                    "addonName addonVersion status health serviceAccountRoleArn podIdentityAssociations")}],
                    self.aws_findings(name, row, {"ACTIVE"}))
            self.attempt("aws.addon." + name, addon)
        for name in profiles:
            def fargate(name=name):
                row = self.cli.call("eks", "describe-fargate-profile", {"clusterName": self.cluster, "fargateProfileName": name})["fargateProfile"]
                roles.add(row.get("podExecutionRoleArn"))
                self.record("aws.fargate." + name, [{"kind": "fargate", "data": pick(row,
                    "fargateProfileName status subnets selectors podExecutionRoleArn health")}], self.aws_findings(name, row, {"ACTIVE"}))
            self.attempt("aws.fargate." + name, fargate)
        entries = self.listing("aws.access_entries", "eks", "list-access-entries", "accessEntries", {"clusterName": self.cluster})
        for index, principal in enumerate(entries):
            self.attempt("aws.access_policies." + str(index), lambda p=principal, n=index: self.listing(
                "aws.access_policies." + str(n), "eks", "list-associated-access-policies", "associatedAccessPolicies",
                {"clusterName": self.cluster, "principalArn": p}))
        vpc = data.get("resourcesVpcConfig", {}).get("vpcId")
        if vpc:
            filters = [{"Name": "vpc-id", "Values": [vpc]}]
            for operation, key, fields in (
                ("describe-subnets", "Subnets", "SubnetId VpcId AvailabilityZone AvailableIpAddressCount CidrBlock State MapPublicIpOnLaunch"),
                ("describe-route-tables", "RouteTables", "RouteTableId VpcId Associations Routes"),
                ("describe-network-acls", "NetworkAcls", "NetworkAclId VpcId Associations Entries"),
                ("describe-security-groups", "SecurityGroups", "GroupId GroupName VpcId IpPermissions IpPermissionsEgress"),
            ):
                component = "aws." + key.lower()
                rows = self.listing(component, "ec2", operation, key, {"Filters": filters}, fields, token="NextToken")
                if key == "Subnets":
                    findings = [{"code": "subnet_low_available_ips", "severity": "warning", "resource": row["SubnetId"]}
                                for row in rows if row.get("AvailableIpAddressCount", 100) < 16]
                    if findings:
                        self.record(component + ".analysis", [], findings)
                if key == "RouteTables":
                    findings = [{"code": "route_blackhole", "severity": "warning", "resource": row["RouteTableId"]}
                                for row in rows if any(route.get("State") == "blackhole" for route in row.get("Routes", []))]
                    if findings:
                        self.record(component + ".analysis", [], findings)
        self.listing("aws.instances", "ec2", "describe-instances", "Reservations",
                     {"Filters": [{"Name": "tag:eks:cluster-name", "Values": [self.cluster]}]},
                     fields="Instances", token="NextToken")
        for name in sorted(asgs):
            self.listing("aws.asg." + name, "autoscaling", "describe-auto-scaling-groups", "AutoScalingGroups",
                         {"AutoScalingGroupNames": [name]}, "AutoScalingGroupName MinSize MaxSize DesiredCapacity Instances SuspendedProcesses", token="NextToken")
        for index, role in enumerate(sorted(r for r in roles if r)):
            name = role.rsplit("/", 1)[-1]
            self.attempt("aws.role." + str(index), lambda n=name, i=index: self.role(n, i))

    def role(self, name, index):
        row = self.cli.call("iam", "get-role", {"RoleName": name})["Role"]
        self.record("aws.role." + str(index), [{"kind": "iam_role", "data": pick(row, "RoleName Arn AssumeRolePolicyDocument PermissionsBoundary")}])
        self.listing("aws.role_policies." + str(index), "iam", "list-attached-role-policies", "AttachedPolicies",
                     {"RoleName": name}, token="Marker")
        self.listing("aws.inline_policy_names." + str(index), "iam", "list-role-policies", "PolicyNames",
                     {"RoleName": name}, token="Marker")

    @staticmethod
    def aws_findings(name, row, healthy):
        findings = []
        if row.get("status") not in healthy:
            findings.append({"resource": name, "code": "aws_resource_not_active", "state": row.get("status"), "severity": "warning"})
        for issue in row.get("health", {}).get("issues", []):
            findings.append({"resource": name, "code": "aws_health_issue", "issue": issue.get("code"), "severity": "error"})
        return findings

    def kubernetes(self, log_target=None):
        if not self.cluster_data:
            return
        try:
            bastion = resolve_bastion(self.account, self.cli.region, self.cluster)
            validate_bastion(self.cli, bastion)
        except CollectionError as exc:
            self.record("kubernetes", [], complete=False, code=exc.code)
            return
        base = {"cluster": self.cluster, "cluster_arn": self.cluster_data["arn"],
                "account_id": self.cli.identity["Account"], "region": self.cli.region}
        kinds = ["logs"] if log_target else list(PROFILES.get(self.profile, PATHS))
        if self.profile != "full" and not log_target:
            self.record("profile", [], scope=self.profile, excluded_kinds=sorted(set(PATHS)-set(kinds)))
        collected, complete_kinds = [], set()
        for kind in kinds:
            component = "kubernetes." + kind
            def collect(kind=kind, component=component):
                payload = {**base, "kind": kind}
                if log_target:
                    payload["log_target"] = log_target
                result = (run_recipe(self.cli, bastion, payload, self.emit) if log_target
                          else self.remote_pages(bastion, payload))
                code = result.get("error")
                crd_names = {row["name"] for row in collected if row.get("kind") == "customresourcedefinitions"}
                expected_crd = OPTIONAL_CRDS.get(kind)
                absent = (kind in OPTIONAL and code == "api_not_found" and expected_crd is not None
                          and "customresourcedefinitions" in complete_kinds and expected_crd not in crd_names)
                complete = result["complete"] or absent
                rows = result.get("items", [])
                if result["complete"] and not result.get("output_truncated"):
                    complete_kinds.add(kind)
                collected.extend(rows)
                self.record(component, rows, result.get("findings", []), complete=complete,
                            code=None if absent else code, observed=result.get("observed", len(rows)),
                            output_truncated=result.get("output_truncated", False),
                            finding_count=result.get("finding_count", len(result.get("findings", []))),
                            finding_severities=result.get("finding_severities", {}), authentication_role=result.get("authentication_role"),
                            applicability="api_absent" if absent else "present_or_unknown", identity=result.get("identity"))
                return result
            result = self.attempt(component, collect)
            if result and result.get("error") in {"remote_account_mismatch", "remote_identity_mismatch", "remote_cluster_mismatch",
                                                  "remote_dependency_or_timeout", "remote_aws_access_denied",
                                                  "kubernetes_timeout", "kubernetes_unauthorized", "dns_unavailable"}:
                self.record("kubernetes.remaining", [], complete=False, code="remote_preflight_failed")
                break
        if not log_target:
            required = {"pods", "services", "endpointslices", "persistentvolumeclaims", "nodes"}
            if required <= set(kinds):
                self.record("kubernetes.correlations", [], correlate(collected, complete_kinds),
                        complete={"pods", "services", "endpointslices", "persistentvolumeclaims", "nodes"} <= complete_kinds,
                        scope="service endpoints, pod PVC dependencies and node readiness; samples do not establish absence")
            discovered = []
            for row in collected:
                if row.get("kind") in {"pods", "deployments", "daemonsets"}:
                    for marker, component in COMPONENTS.items():
                        if marker in row.get("name", ""):
                            discovered.append({"kind": "component", "component_type": component,
                                               "name": row["name"], "namespace": row["namespace"]})
            if "pods" in kinds:
                self.record("kubernetes.components", discovered[:200], complete="pods" in complete_kinds,
                            scope="name-based discovery; managed Auto Mode components may not appear as pods")
            ids = sorted({n['provider_id'].rsplit('/', 1)[-1] for n in collected
                          if n.get('kind') == 'nodes' and (n.get('provider_id') or '').startswith('aws://')})
            for start in range(0, len(ids), 50):
                def capacity(start=start):
                    reservations = self.listing('aws.node_capacity.' + str(start), 'ec2', 'describe-instances', 'Reservations',
                        {'InstanceIds': ids[start:start+50]}, fields='Instances', token='NextToken')
                    instances = {i['InstanceId']: i for r in reservations for i in r.get('Instances', [])}
                    for node in collected:
                        if node.get('kind') != 'nodes':
                            continue
                        instance = instances.get((node.get('provider_id') or '').rsplit('/', 1)[-1])
                        if instance:
                            life = instance.get('InstanceLifecycle')
                            node['ec2_capacity_type'] = 'spot' if life == 'spot' else ('on-demand' if life is None else 'unknown')
                self.attempt('aws.node_capacity.' + str(start), capacity)
            self.record("kubernetes.capacity_migration", summarize(collected, complete_kinds),
                        complete={"nodes", "pods"} <= complete_kinds if self.profile != "nodes" else "nodes" in complete_kinds,
                        scope="Placement and instantaneous capacity; no scheduler simulation or drain authorization")
            if self.profile == "full":
                self.dependencies(collected)

    def remote_pages(self, bastion, payload):
        """Aggregate server-paginated SSM results, retrying oversized pages at the same snapshot."""
        aggregate = {"items": [], "findings": [], "observed": 0, "finding_count": 0,
                     "finding_severities": {}, "complete": True, "output_truncated": False}
        cursor, version, seen, page_size, pages = "", None, set(), 100, 0
        for _ in range(40):  # At most 20 data pages plus bounded page-size reductions.
            try:
                result = run_recipe(self.cli, bastion, {**payload, "paged": True, "page_token": cursor,
                                    "page_size": page_size, "resource_version": version}, self.emit)
            except CollectionError as exc:
                aggregate.update(complete=False, error=exc.code)
                if exc.code in {"cancelled", "deadline_exceeded", "ssm_submission_unconfirmed"}:
                    self.record("kubernetes." + payload["kind"], aggregate["items"], aggregate["findings"],
                                complete=False, code=exc.code, observed=aggregate["observed"])
                    raise
                break
            if version and result.get("resource_version") and version != result["resource_version"]:
                aggregate.update(complete=False, error="kubernetes_snapshot_changed")
                break
            if result.get("output_truncated") and page_size > 1 and result.get("resource_version"):
                version = result["resource_version"]
                page_size = max(1, page_size // 2)
                continue
            pages += 1
            aggregate["items"].extend(result.get("items", []))
            aggregate["findings"].extend(result.get("findings", []))
            aggregate["observed"] += result.get("observed", len(result.get("items", [])))
            aggregate["finding_count"] += result.get("finding_count", len(result.get("findings", [])))
            aggregate["identity"] = result.get("identity")
            aggregate["authentication_role"] = result.get("authentication_role")
            for severity, count in result.get("finding_severities", {}).items():
                aggregate["finding_severities"][severity] = aggregate["finding_severities"].get(severity, 0) + count
            aggregate["output_truncated"] |= result.get("output_truncated", False)
            if not result["complete"] or result.get("output_truncated"):
                aggregate.update(complete=False, error=result.get("error") or "remote_evidence_limit")
                break
            token = result.get("next_token")
            if not token:
                break
            if token in seen or pages >= 20:
                aggregate.update(complete=False, error="remote_page_limit_or_cycle")
                break
            seen.add(token)
            cursor, version = token, result.get("resource_version")
        else:
            aggregate.update(complete=False, error="remote_page_limit")
        return aggregate

    def dependencies(self, items):
        instance_ids = sorted({i["provider_id"].rsplit("/", 1)[-1] for i in items
                               if i.get("kind") == "nodes" and (i.get("provider_id") or "").startswith("aws://")})
        for start in range(0, len(instance_ids), 50):
            rows = self.listing("aws.node_status." + str(start), "ec2", "describe-instance-status", "InstanceStatuses",
                         {"InstanceIds": instance_ids[start:start + 50], "IncludeAllInstances": True},
                         "InstanceId InstanceState InstanceStatus SystemStatus AttachedEbsStatus Events", token="NextToken")
            findings = []
            for row in rows:
                for check in ("InstanceStatus", "SystemStatus", "AttachedEbsStatus"):
                    if row.get(check, {}).get("Status") == "impaired":
                        findings.append({"code": "ec2_status_impaired", "check": check, "severity": "error", "resource": row["InstanceId"]})
                if row.get("Events"):
                    findings.append({"code": "ec2_scheduled_events", "severity": "warning", "resource": row["InstanceId"]})
            if findings:
                self.record("aws.node_status_analysis." + str(start), [], findings)
        volumes = sorted({i.get("csi", {}).get("volumeHandle") for i in items
                          if i.get("kind") == "persistentvolumes" and i.get("csi", {}).get("driver") == "ebs.csi.aws.com"
                          and i.get("csi", {}).get("volumeHandle")})
        for start in range(0, len(volumes), 50):
            self.listing("aws.volumes." + str(start), "ec2", "describe-volumes", "Volumes",
                         {"VolumeIds": volumes[start:start + 50]}, "VolumeId State Size VolumeType AvailabilityZone Attachments Encrypted Iops Throughput", token="NextToken")
        dns = {entry.get("hostname") for i in items for entry in i.get("load_balancer", {}).get("ingress", []) if entry.get("hostname")}
        if dns:
            def load_balancers():
                matched = []
                for page in self.cli.pages("elbv2", "describe-load-balancers", "LoadBalancers", token="Marker", output_token="NextMarker"):
                    matched.extend(row for row in page if row.get("DNSName") in dns)
                self.record("aws.load_balancers", [{"kind": "load_balancer", "data": pick(row,
                    "LoadBalancerArn DNSName State Type Scheme VpcId SecurityGroups AvailabilityZones")} for row in matched],
                    complete=len(matched) == len(dns), scope="ELBv2 matched by Kubernetes hostname; classic ELB not supported")
                for index, row in enumerate(matched):
                    groups = self.listing("aws.target_groups." + str(index), "elbv2", "describe-target-groups", "TargetGroups",
                        {"LoadBalancerArn": row["LoadBalancerArn"]}, "TargetGroupArn Protocol Port TargetType HealthCheckPath", token="Marker", output_token="NextMarker")
                    for group in groups:
                        health = self.cli.call("elbv2", "describe-target-health", {"TargetGroupArn": group["TargetGroupArn"]})["TargetHealthDescriptions"]
                        findings = [{"code": "load_balancer_target_unhealthy", "severity": "warning", "resource": group["TargetGroupArn"],
                                     "state": h.get("TargetHealth", {}).get("State")}
                                    for h in health if h.get("TargetHealth", {}).get("State") in {"unhealthy", "unavailable"}]
                        matching = [i for i in items if i.get("kind") == "services" and any(e.get("hostname") == row.get("DNSName") for e in i.get("load_balancer", {}).get("ingress", []))]
                        context = [{"namespace": svc.get("namespace", ""), "service": svc.get("name", ""),
                                    "ready_endpoints": sum(e.get("ready", 0) for e in items if e.get("kind") == "endpointslices" and e.get("namespace") == svc.get("namespace") and e.get("service") == svc.get("name")),
                                    "zero_replica_workloads_same_name": [w["name"] for w in items if w.get("kind") in {"deployments", "statefulsets", "rollouts"} and w.get("namespace") == svc.get("namespace") and w.get("name") == svc.get("name") and w.get("desired") == 0],
                                    "endpoint_coverage_complete": self.coverage.get("kubernetes.endpointslices", {}).get("complete", False)} for svc in matching]
                        for finding in findings:
                            finding["service_context"] = context
                        self.record("aws.target_health." + group["TargetGroupArn"].rsplit("/", 1)[-1],
                                    [{"kind": "target_health", "data": h} for h in health], findings)
            self.attempt("aws.load_balancers", load_balancers)
