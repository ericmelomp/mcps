"""Reproducible synthetic payload benchmark; never accesses AWS."""

import json
import os
import tempfile
from pathlib import Path

from aws_ops_mcp.contracts import encoded
from aws_ops_mcp.ec2 import normalize
from aws_ops_mcp.service import Service


def main():
    items = [normalize({"InstanceId": f"i-{i:017d}", "InstanceType": "t3.small",
                        "State": {"Name": "running"}, "Placement": {"AvailabilityZone": "us-east-1a"}})
             for i in range(1000)]
    previous = os.environ.get("AWS_OPS_CONFIG")
    try:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "accounts.json"
            path.write_text(json.dumps({"accounts": {"synthetic": {
                "account_id": "000000000000", "regions": ["us-east-1"]
            }}}), encoding="utf-8")
            os.environ["AWS_OPS_CONFIG"] = str(path)
            result = Service(run=lambda *_: (items, [], 10, True)).query("synthetic", "us-east-1")
        baseline, summary = len(encoded(items)), len(encoded(result))
        print(json.dumps({"synthetic_instances": len(items), "normalized_input_bytes": baseline,
                          "summary_bytes": summary, "payload_reduction_percent": round(100 * (1 - summary / baseline), 2),
                          "measures_tokens": False}, indent=2))
    finally:
        if previous is None:
            os.environ.pop("AWS_OPS_CONFIG", None)
        else:
            os.environ["AWS_OPS_CONFIG"] = previous


if __name__ == "__main__":
    main()
