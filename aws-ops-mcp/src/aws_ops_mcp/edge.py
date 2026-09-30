"""Read-only edge configuration evidence. No DNS, TLS or application probes."""

import re
import time
from collections import Counter

from .config import ConfigurationError, resolve
from .contracts import bounded, envelope
from .eks_cli import CLI, CollectionError


def wildcard(pattern, value):
    # CloudFront supports only * and ?, not shell bracket expressions.
    expression = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
    return re.fullmatch(expression, value) is not None


class Edge:
    def __init__(self, store, factory=CLI):
        self.store, self.factory = store, factory

    def query(self, account, region, kind, **target):
        result = envelope(account, region)
        result["coverage"].update(scope="AWS configuration only; not end-to-end gRPC health",
            exclusions=["DNS resolution", "TLS handshake", "WAF decisions", "Kubernetes routing", "application RPC"])
        try:
            config = resolve(account, region)
            cli = self.factory(config, region, deadline=time.monotonic() + 60)
            getattr(self, kind)(cli, result, **target)
        except ConfigurationError:
            result["errors"].append({"code": "configuration_invalid"})
        except CollectionError as exc:
            result["errors"].append({"code": exc.code})
        except Exception:
            result["errors"].append({"code": "internal_error"})
        if result["errors"]:
            result["coverage"]["complete"] = False
            result["status"] = "partial" if result.get("items") else "error"
        elif result["findings"]:
            result["status"] = "degraded"
        result["summary"]["finding_count"] = len(result["findings"])
        if result.get("items"):
            key = self.store.put(account, region, result["items"], result["coverage"])
            if key:
                result["evidence_id"] = key
            else:
                result["coverage"]["evidence_unavailable"] = True
        return bounded(result)

    @staticmethod
    def add(result, item):
        items = result.setdefault("items", [])
        if len(items) >= 2000:
            raise CollectionError("item_limit")
        items.append(item)

    @staticmethod
    def finding(result, code, resource):
        if len(result["findings"]) < 200:
            result["findings"].append({"code": code, "resource": resource})
        else:
            result["coverage"]["output_truncated"] = True

    def cloudfront(self, cli, result, hostname="", distribution_id="", path=""):
        result["coverage"]["service_scope"] = "CloudFront global; region selects authorized credentials"
        if path and (not path.startswith("/") or any(x in path for x in ("%", "?", "#", "\\", "//"))
                     or any(x in {".", ".."} for x in path.split("/"))):
            raise CollectionError("path_requires_canonical_literal")
        if not distribution_id:
            matches, marker, seen = [], "", set()
            for _ in range(100):
                params = {"MaxItems": "100"}
                if marker:
                    params["Marker"] = marker
                page = cli.call("cloudfront", "list-distributions", params).get("DistributionList", {})
                for item in page.get("Items", []):
                    aliases = item.get("Aliases", {}).get("Items", [])
                    self.add(result, {"kind": "distribution", "id": item["Id"], "domain": item["DomainName"],
                        "aliases": aliases, "enabled": item.get("Enabled"), "status": item.get("Status")})
                    if hostname and (hostname.lower().rstrip(".") == item["DomainName"].lower()
                        or any(wildcard(alias.lower(), hostname.lower().rstrip(".")) for alias in aliases)):
                        matches.append(item["Id"])
                if not page.get("IsTruncated"):
                    break
                marker = page.get("NextMarker")
                if not marker or marker in seen:
                    raise CollectionError("pagination_incomplete")
                seen.add(marker)
            else:
                raise CollectionError("page_limit")
            result["summary"]["observed_distributions"] = len(result.get("items", []))
            if not hostname:
                result["summary"]["mode"] = "discovery_only; supply hostname or distribution_id for analysis"
                return
            if len(matches) != 1:
                raise CollectionError("distribution_not_found" if not matches else "ambiguous_alias_use_distribution_id")
            distribution_id = matches[0]
        data = cli.call("cloudfront", "get-distribution", {"Id": distribution_id})["Distribution"]
        config = data["DistributionConfig"]
        version = config.get("HttpVersion", "http1.1")
        result["summary"].update(distribution_id=distribution_id, http_version=version,
            deployment_status=data.get("Status"), enabled=config.get("Enabled"), web_acl_id=config.get("WebACLId"),
            selected_path=path or None, interpretation="Configuration requirements only; no RPC executed")
        self.add(result, {"kind": "distribution_config", **result["summary"]})
        if not config.get("Enabled"):
            self.finding(result, "distribution_disabled", distribution_id)
        if data.get("Status") != "Deployed":
            self.finding(result, "distribution_not_fully_deployed", distribution_id)
        if version not in {"http2", "http2and3"}:
            self.finding(result, "http2_not_enabled", distribution_id)
        origins = {x["Id"]: x for x in config.get("Origins", {}).get("Items", [])}
        behaviors = list(config.get("CacheBehaviors", {}).get("Items", []))
        behaviors.append({**config["DefaultCacheBehavior"], "PathPattern": "*"})
        if path:
            behaviors = [next(x for x in behaviors if wildcard(x["PathPattern"].lstrip("/"), path.lstrip("/")))]
        for behavior in behaviors:
            pattern = behavior["PathPattern"]
            origin = origins.get(behavior["TargetOriginId"], {})
            custom = origin.get("CustomOriginConfig", {})
            grpc = behavior.get("GrpcConfig", {}).get("Enabled", False)
            methods = behavior.get("AllowedMethods", {}).get("Items", [])
            record = {"kind": "behavior", "pattern": pattern, "grpc_enabled": grpc,
                "allowed_methods": methods, "viewer_protocol_policy": behavior.get("ViewerProtocolPolicy"),
                "origin_id": behavior["TargetOriginId"], "origin_domain": origin.get("DomainName"),
                "origin_protocol_policy": custom.get("OriginProtocolPolicy"),
                "origin_https_port": custom.get("HTTPSPort"), "origin_path": origin.get("OriginPath"),
                "cache_policy_id": behavior.get("CachePolicyId"),
                "origin_request_policy_id": behavior.get("OriginRequestPolicyId"),
                "lambda_association_count": behavior.get("LambdaFunctionAssociations", {}).get("Quantity", 0),
                "origin_shield_enabled": origin.get("OriginShield", {}).get("Enabled", False)}
            self.add(result, record)
            if not grpc:
                self.finding(result, "grpc_disabled", pattern)
            if "POST" not in methods:
                self.finding(result, "post_not_allowed", pattern)
            if custom:
                if custom.get("OriginProtocolPolicy") == "http-only":
                    self.finding(result, "origin_https_required", pattern)
            else:
                result["errors"].append({"code": "origin_type_not_assessed", "resource": behavior["TargetOriginId"]})
        result["summary"]["assessed_behaviors"] = len(behaviors)
        result["summary"]["behavior_scope"] = "selected path" if path else "all behaviors; findings may not affect intended RPC"

    def elbv2(self, cli, result, load_balancer_arn="", dns_name=""):
        parameters = {"LoadBalancerArns": [load_balancer_arn]} if load_balancer_arn else {}
        matches = []
        for page in cli.pages("elbv2", "describe-load-balancers", "LoadBalancers", parameters,
                              token="Marker", output_token="NextMarker"):
            for lb in page:
                self.add(result, {"kind": "load_balancer", **{key: lb.get(key) for key in
                    ("LoadBalancerArn", "DNSName", "Type", "Scheme", "State", "VpcId")}})
                if load_balancer_arn or (dns_name and lb.get("DNSName", "").lower() == dns_name.lower().rstrip(".")):
                    matches.append(lb)
        if not load_balancer_arn and not dns_name:
            result["summary"]["mode"] = "discovery_only; supply load_balancer_arn or dns_name"
            return
        if len(matches) != 1:
            raise CollectionError("load_balancer_not_found" if not matches else "ambiguous_load_balancer")
        lb = matches[0]
        arn = lb["LoadBalancerArn"]
        result["summary"].update(load_balancer_arn=arn, type=lb["Type"],
            interpretation="Listener and target configuration; routing selection and RPC health not proven")
        if lb.get("State", {}).get("Code") != "active":
            self.finding(result, "load_balancer_not_active", arn)

        def attempt(operation, function):
            try:
                function()
            except CollectionError as exc:
                result["errors"].append({"code": exc.code, "operation": operation})

        def attributes():
            values = cli.call("elbv2", "describe-load-balancer-attributes", {"LoadBalancerArn": arn})["Attributes"]
            allowed = {"routing.http2.enabled", "idle_timeout.timeout_seconds", "load_balancing.cross_zone.enabled"}
            self.add(result, {"kind": "attributes", "values": {v["Key"]: v["Value"] for v in values if v["Key"] in allowed}})
            if any(v["Key"] == "routing.http2.enabled" and v["Value"] == "false" for v in values):
                self.finding(result, "alb_http2_disabled", arn)

        def actions(values):
            return [{"type": x["Type"], "target_group_arn": x.get("TargetGroupArn"),
                "weighted_targets": [{"arn": t.get("TargetGroupArn"), "weight": t.get("Weight")}
                    for t in x.get("ForwardConfig", {}).get("TargetGroups", [])]} for x in values]

        def rules(listener):
            for page in cli.pages("elbv2", "describe-rules", "Rules", {"ListenerArn": listener},
                                  token="Marker", output_token="NextMarker"):
                for rule in page:
                    self.add(result, {"kind": "rule", "listener_arn": listener,
                        "priority": rule.get("Priority"), "rule_arn": rule["RuleArn"],
                        "condition_fields": [c.get("Field") for c in rule.get("Conditions", [])],
                        "host_path_conditions": [c for c in rule.get("Conditions", []) if c.get("Field") in {"host-header", "path-pattern"}],
                        "actions": actions(rule.get("Actions", []))})

        def listeners():
            for page in cli.pages("elbv2", "describe-listeners", "Listeners", {"LoadBalancerArn": arn},
                                  token="Marker", output_token="NextMarker"):
                for listener in page:
                    self.add(result, {"kind": "listener", "arn": listener["ListenerArn"],
                        "port": listener["Port"], "protocol": listener["Protocol"],
                        "alpn_policy": listener.get("AlpnPolicy", []),
                        "actions": actions(listener.get("DefaultActions", []))})
                    if lb["Type"] == "application":
                        attempt("describe-rules", lambda: rules(listener["ListenerArn"]))

        def health(group):
            data = cli.call("elbv2", "describe-target-health", {"TargetGroupArn": group})
            targets = data.get("TargetHealthDescriptions", [])
            counts = Counter(t.get("TargetHealth", {}).get("State", "unknown") for t in targets)
            self.add(result, {"kind": "target_health_summary", "target_group_arn": group, "counts": dict(counts)})
            for target in targets:
                self.add(result, {"kind": "target_health", "target_group_arn": group,
                    "target": target.get("Target"), "state": target.get("TargetHealth", {}).get("State"),
                    "reason": target.get("TargetHealth", {}).get("Reason")})
            if not targets or any(state != "healthy" for state in counts):
                self.finding(result, "targets_not_all_healthy", group)

        def groups():
            for page in cli.pages("elbv2", "describe-target-groups", "TargetGroups", {"LoadBalancerArn": arn},
                                  token="Marker", output_token="NextMarker"):
                for group in page:
                    group_arn = group["TargetGroupArn"]
                    self.add(result, {"kind": "target_group", **{key: group.get(key) for key in
                        ("TargetGroupArn", "Protocol", "Port", "ProtocolVersion", "TargetType", "HealthCheckProtocol", "HealthCheckPath", "Matcher")}})
                    if lb["Type"] == "application" and group.get("ProtocolVersion", "HTTP1") == "HTTP1":
                        self.finding(result, "target_group_http1_not_grpc_compatible", group_arn)
                    attempt("describe-target-health", lambda: health(group_arn))

        attempt("describe-load-balancer-attributes", attributes)
        attempt("describe-listeners", listeners)
        attempt("describe-target-groups", groups)
