"""Local stdio MCP endpoint. Importing this module performs no AWS calls."""

import logging
from typing import Annotated

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from .contracts import envelope
from .service import Service

mcp = FastMCP("AWS Ops MCP", instructions="Read-only EC2 checks. Start with capabilities. Report partial coverage and unsupported analyses explicitly. Use evidence_get only when the summary is insufficient.")
service = Service()
Alias = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$")]
Region = Annotated[str, Field(min_length=5, max_length=32, pattern=r"^[a-z]{2}(?:-[a-z]+)+-\d+$")]
annotations = ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=True)


@mcp.tool(structured_output=False, annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
def capabilities() -> str:
    """List supported analyses without accessing AWS. No automatic code generation."""
    from .contracts import encoded
    result = envelope()
    result["summary"] = {
        "tools": ["capabilities", "ec2_inventory", "ec2_health", "evidence_get"],
        "services": {"ec2": ["inventory", "instance_state", "instance_system_and_available_ebs_checks", "scheduled_events"]},
        "unsupported": "Any service or analysis not listed; request assisted development in the repository",
        "extension": "Agent edits code, tests and restarts server; no self-modification or IAM grants",
        "limits": {"summary_bytes": 12288, "evidence_page_bytes": 24576, "evidence_page_items": 50,
                   "collection_seconds": 60, "pages": 100, "instances": 10000, "evidence_ttl_seconds": 900},
    }
    return encoded(result).decode()


@mcp.tool(structured_output=False, annotations=annotations)
def ec2_inventory(account: Alias, region: Region) -> str:
    """Compact EC2 inventory for one configured account alias and allowed region."""
    from .contracts import encoded
    return encoded(service.query(account, region)).decode()


@mcp.tool(structured_output=False, annotations=annotations)
def ec2_health(account: Alias, region: Region) -> str:
    """EC2 state, status checks and scheduled events. Not overall application health."""
    from .contracts import encoded
    return encoded(service.query(account, region, health=True)).decode()


@mcp.tool(structured_output=False, annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
def evidence_get(
    evidence_id: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")],
    offset: Annotated[int, Field(ge=0, le=10000)] = 0,
    limit: Annotated[int, Field(ge=1, le=50)] = 50,
) -> str:
    """Read a bounded page of normalized evidence from this server session; expires after 15 minutes."""
    from .contracts import encoded
    return encoded(service.store.get(evidence_id, offset, limit)).decode()


def main():
    logging.basicConfig(level=logging.WARNING)
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
