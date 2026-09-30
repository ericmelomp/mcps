"""Pure Kubernetes normalization and checks; also shipped to the SSM recipe.

Never retain full specs, annotations, environment, Secret objects or event messages.
"""

PATHS = {
    "customresourcedefinitions": "/apis/apiextensions.k8s.io/v1/customresourcedefinitions",
    "nodes": "/api/v1/nodes", "pods": "/api/v1/pods", "events": "/api/v1/events",
    "services": "/api/v1/services", "persistentvolumeclaims": "/api/v1/persistentvolumeclaims",
    "persistentvolumes": "/api/v1/persistentvolumes", "resourcequotas": "/api/v1/resourcequotas",
    "deployments": "/apis/apps/v1/deployments", "statefulsets": "/apis/apps/v1/statefulsets",
    "daemonsets": "/apis/apps/v1/daemonsets", "jobs": "/apis/batch/v1/jobs",
    "cronjobs": "/apis/batch/v1/cronjobs", "horizontalpodautoscalers": "/apis/autoscaling/v2/horizontalpodautoscalers",
    "poddisruptionbudgets": "/apis/policy/v1/poddisruptionbudgets",
    "endpointslices": "/apis/discovery.k8s.io/v1/endpointslices",
    "ingresses": "/apis/networking.k8s.io/v1/ingresses", "networkpolicies": "/apis/networking.k8s.io/v1/networkpolicies",
    "storageclasses": "/apis/storage.k8s.io/v1/storageclasses",
    "serviceaccounts": "/api/v1/serviceaccounts",
    "nodepools": "/apis/karpenter.sh/v1/nodepools", "nodeclaims": "/apis/karpenter.sh/v1/nodeclaims",
    "ec2nodeclasses": "/apis/karpenter.k8s.aws/v1/ec2nodeclasses",
    "node_metrics": "/apis/metrics.k8s.io/v1beta1/nodes", "pod_metrics": "/apis/metrics.k8s.io/v1beta1/pods",
}
OPTIONAL = {"nodepools", "nodeclaims", "ec2nodeclasses", "node_metrics", "pod_metrics"}
COMPONENTS = {
    "coredns": "dns", "aws-node": "vpc_cni", "kube-proxy": "service_proxy", "ebs-csi": "ebs_csi",
    "efs-csi": "efs_csi", "aws-load-balancer-controller": "load_balancer_controller",
    "ingress-nginx": "ingress", "metrics-server": "metrics", "karpenter": "karpenter",
    "cluster-autoscaler": "cluster_autoscaler", "cloudwatch": "observability", "fluent-bit": "observability",
}


def normalize(kind, obj):
    meta, spec, status = obj.get("metadata", {}), obj.get("spec", {}), obj.get("status", {})
    item = {"kind": kind, "name": meta.get("name", ""), "namespace": meta.get("namespace", ""),
            "deleting": bool(meta.get("deletionTimestamp"))}
    item["conditions"] = [{k: c[k] for k in ("type", "status", "reason", "lastTransitionTime") if k in c}
                          for c in status.get("conditions", [])[:30]]
    if kind == "pods":
        item.update(phase=status.get("phase", "Unknown"), node=spec.get("nodeName"),
                    owners=[{"kind": o.get("kind"), "name": o.get("name")} for o in meta.get("ownerReferences", [])[:5]],
                    volumes=[v["persistentVolumeClaim"]["claimName"] for v in spec.get("volumes", []) if "persistentVolumeClaim" in v],
                    labels={k: v for k, v in meta.get("labels", {}).items() if k in {"app", "k8s-app", "app.kubernetes.io/name"}})
        item["containers"] = [{"name": c.get("name"), "ready": c.get("ready", False),
                               "restarts": c.get("restartCount", 0),
                               "waiting": c.get("state", {}).get("waiting", {}).get("reason"),
                               "terminated": c.get("state", {}).get("terminated", {}).get("reason"),
                               "last_terminated": c.get("lastState", {}).get("terminated", {}).get("reason")}
                              for c in status.get("initContainerStatuses", []) + status.get("containerStatuses", [])]
        item["resources"] = [{"name": c.get("name"), "requests": c.get("resources", {}).get("requests", {}),
                              "limits": c.get("resources", {}).get("limits", {})}
                             for c in spec.get("initContainers", []) + spec.get("containers", [])]
    elif kind == "nodes":
        item.update(capacity=status.get("capacity", {}), allocatable=status.get("allocatable", {}),
                    provider_id=spec.get("providerID"), unschedulable=spec.get("unschedulable", False),
                    taints=spec.get("taints", []), node_info=status.get("nodeInfo", {}))
    elif kind in {"deployments", "statefulsets", "daemonsets"}:
        item.update(desired=status.get("desiredNumberScheduled", 0) if kind == "daemonsets" else spec.get("replicas", 1),
                    ready=status.get("numberReady", 0) if kind == "daemonsets" else status.get("readyReplicas", 0),
                    updated=status.get("updatedNumberScheduled", 0) if kind == "daemonsets" else status.get("updatedReplicas", 0),
                    generation=meta.get("generation"), observed_generation=status.get("observedGeneration"))
    elif kind == "events":
        item.update(type=obj.get("type"), reason=obj.get("reason"), count=obj.get("count", 1),
                    last_seen=obj.get("lastTimestamp") or obj.get("eventTime"),
                    object={k: obj.get("involvedObject", {}).get(k) for k in ("kind", "name", "namespace")})
    elif kind in {"persistentvolumeclaims", "persistentvolumes"}:
        item.update(phase=status.get("phase"), storage_class=spec.get("storageClassName"),
                    volume=spec.get("volumeName"), capacity=status.get("capacity", spec.get("capacity", {})),
                    csi={k: spec.get("csi", {}).get(k) for k in ("driver", "volumeHandle")},
                    claim={k: spec.get("claimRef", {}).get(k) for k in ("name", "namespace")})
    elif kind == "services":
        item.update(type=spec.get("type"), selector=spec.get("selector", {}), cluster_ip=spec.get("clusterIP"),
                    ports=[{k: p.get(k) for k in ("port", "targetPort", "protocol")} for p in spec.get("ports", [])],
                    load_balancer=status.get("loadBalancer", {}))
    elif kind == "endpointslices":
        endpoints = obj.get("endpoints") or []
        item.update(service=meta.get("labels", {}).get("kubernetes.io/service-name"),
                    endpoints=len(endpoints),
                    ready=sum((e.get("conditions") or {}).get("ready") is not False for e in endpoints))
    elif kind == "ingresses":
        item.update(ingress_class=spec.get("ingressClassName"), load_balancer=status.get("loadBalancer", {}))
    elif kind == "networkpolicies":
        item.update(pod_selector=spec.get("podSelector", {}), policy_types=spec.get("policyTypes", []),
                    ingress_rules=len(spec.get("ingress", [])), egress_rules=len(spec.get("egress", [])))
    elif kind == "storageclasses":
        item.update(provisioner=obj.get("provisioner"), binding_mode=obj.get("volumeBindingMode"), reclaim_policy=obj.get("reclaimPolicy"))
    elif kind == "resourcequotas":
        item.update(hard=status.get("hard", {}), used=status.get("used", {}))
    elif kind == "horizontalpodautoscalers":
        item.update(min_replicas=spec.get("minReplicas", 1), max_replicas=spec.get("maxReplicas"),
                    current=status.get("currentReplicas"), desired=status.get("desiredReplicas"))
    elif kind == "poddisruptionbudgets":
        item.update(disruptions_allowed=status.get("disruptionsAllowed"), current_healthy=status.get("currentHealthy"),
                    desired_healthy=status.get("desiredHealthy"))
    elif kind in {"jobs", "cronjobs"}:
        item.update(active=status.get("active"), failed=status.get("failed", 0), succeeded=status.get("succeeded", 0),
                    suspended=spec.get("suspend", False), last_schedule=status.get("lastScheduleTime"))
    elif kind in {"nodepools", "nodeclaims", "ec2nodeclasses"}:
        item.update(resources=status.get("resources", {}), provider_id=status.get("providerID"))
    elif kind in {"node_metrics", "pod_metrics"}:
        item.update(timestamp=obj.get("timestamp"), window=obj.get("window"), usage=obj.get("usage"),
                    containers=[{"name": c.get("name"), "usage": c.get("usage")} for c in obj.get("containers", [])])
    elif kind == "customresourcedefinitions":
        item.update(group=spec.get("group"), resource_kind=spec.get("names", {}).get("kind"),
                    served_versions=[v["name"] for v in spec.get("versions", []) if v.get("served")])
    elif kind == "serviceaccounts":
        item.update(iam_role=meta.get("annotations", {}).get("eks.amazonaws.com/role-arn"),
                    automount_token=obj.get("automountServiceAccountToken"))
    return item


def analyze(item):
    kind, findings = item["kind"], []
    def add(code, severity="warning"):
        findings.append({"code": code, "severity": severity, "kind": kind,
                         "name": item["name"], "namespace": item["namespace"]})
    conditions = {c["type"]: c["status"] for c in item.get("conditions", [])}
    if kind == "nodes":
        if conditions.get("Ready") != "True":
            add("node_not_ready", "error")
        for condition in ("MemoryPressure", "DiskPressure", "PIDPressure", "NetworkUnavailable"):
            if conditions.get(condition) == "True":
                add(condition)
    elif kind == "pods" and not item.get("deleting"):
        if item["phase"] in {"Pending", "Failed", "Unknown"}:
            add("pod_" + item["phase"].lower())
        if item["phase"] not in {"Succeeded", "Failed"} and conditions.get("Ready") == "False":
            add("pod_not_ready")
        for c in item["containers"]:
            if c["waiting"] in {"CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull", "CreateContainerConfigError"}:
                add(c["waiting"], "error")
            if c["terminated"] == "OOMKilled" or c["last_terminated"] == "OOMKilled":
                add("container_oom_observed")
    elif kind in {"deployments", "statefulsets", "daemonsets"}:
        if item["ready"] < item["desired"]:
            add("workload_replicas_unavailable")
        if item.get("generation") and (item.get("observed_generation") or 0) < item["generation"]:
            add("controller_generation_pending")
    elif kind == "events" and item["type"] == "Warning":
        add("warning_event_observed", "info")
    elif kind == "persistentvolumeclaims" and item["phase"] != "Bound":
        add("pvc_not_bound")
    elif kind == "persistentvolumes" and item["phase"] == "Failed":
        add("pv_failed", "error")
    elif kind == "jobs" and conditions.get("Failed") == "True":
        add("job_failed", "error")
    elif kind == "horizontalpodautoscalers":
        if conditions.get("ScalingActive") == "False" or conditions.get("AbleToScale") == "False":
            add("hpa_unavailable")
    elif kind in {"nodepools", "nodeclaims", "ec2nodeclasses"}:
        if conditions.get("Ready") != "True":
            add("karpenter_resource_not_ready")
    return findings


def correlate(items, complete_kinds):
    """Only make absence claims when both source collections are complete."""
    findings = []
    slices = {}
    pvcs = {(i["namespace"], i["name"]): i for i in items if i["kind"] == "persistentvolumeclaims"}
    nodes = {i["name"]: i for i in items if i["kind"] == "nodes"}
    for item in items:
        if item["kind"] == "endpointslices":
            key = (item["namespace"], item.get("service"))
            slices[key] = slices.get(key, 0) + item["ready"]
    for item in items:
        codes = []
        if item["kind"] == "services" and {"services", "endpointslices"} <= complete_kinds:
            if item.get("selector") and not slices.get((item["namespace"], item["name"])):
                codes.append("service_without_ready_endpoints")
        if item["kind"] == "pods":
            if "persistentvolumeclaims" in complete_kinds:
                for claim in item.get("volumes", []):
                    pvc = pvcs.get((item["namespace"], claim))
                    if not pvc or pvc.get("phase") != "Bound":
                        codes.append("pod_storage_dependency_unavailable")
            node = nodes.get(item.get("node"))
            if node and any(c.get("type") == "Ready" and c.get("status") != "True" for c in node["conditions"]):
                codes.append("pod_on_unready_node")
        for code in set(codes):
            findings.append({"code": code, "severity": "warning", "kind": item["kind"],
                             "name": item["name"], "namespace": item["namespace"]})
    return findings
