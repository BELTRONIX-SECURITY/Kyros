"""Correos relacionados del dominio (hunter.io)."""

from typing import Any

from kyros.services.base import Context, Service


class Hunter(Service):
    name = "hunter.io"
    key_name = "hunter"

    async def run(self, ctx: Context) -> dict[str, Any]:
        resp = await ctx.client.get(
            "https://api.hunter.io/v2/domain-search",
            params={"domain": ctx.domain, "limit": 10},
            headers={"X-API-KEY": ctx.keys["hunter"]},
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "organizacion": data.get("organization"),
            "correos_relacionados": [e["value"] for e in data.get("emails", [])],
        }
