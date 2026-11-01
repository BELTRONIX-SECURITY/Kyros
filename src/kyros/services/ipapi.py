"""Geolocalización e información de red del dominio (ipapi.co, sin clave)."""

import asyncio
import socket
from typing import Any

from kyros.services.base import Context, Service

_FIELDS = ("ip", "city", "region", "country_name", "org", "asn", "timezone")


class IpApi(Service):
    name = "ipapi.co"

    async def run(self, ctx: Context) -> dict[str, Any]:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(ctx.domain, None, family=socket.AF_INET)
        ip = infos[0][4][0]

        resp = await ctx.client.get(f"https://ipapi.co/{ip}/json/")
        resp.raise_for_status()
        data = resp.json()
        if data.get("error"):
            raise RuntimeError(data.get("reason", "error de ipapi"))
        return {key: data.get(key) for key in _FIELDS}
