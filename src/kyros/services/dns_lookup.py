"""Registros MX, SPF y DMARC del dominio."""

from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver

from kyros.services.base import Context, Service


async def _txt(resolver: dns.asyncresolver.Resolver, name: str) -> list[str]:
    try:
        answer = await resolver.resolve(name, "TXT")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return []
    return [b"".join(r.strings).decode("utf-8", "replace") for r in answer]


class DnsLookup(Service):
    name = "DNS"

    async def run(self, ctx: Context) -> dict[str, Any]:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = min(ctx.timeout, 8.0)

        try:
            answer = await resolver.resolve(ctx.domain, "MX")
            mx = sorted(
                ({"prioridad": r.preference, "host": str(r.exchange).rstrip(".")} for r in answer),
                key=lambda item: item["prioridad"],
            )
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            mx = []

        spf = [t for t in await _txt(resolver, ctx.domain) if t.lower().startswith("v=spf1")]
        dmarc = [
            t
            for t in await _txt(resolver, f"_dmarc.{ctx.domain}")
            if t.lower().startswith("v=dmarc1")
        ]
        return {
            "acepta_correo": bool(mx),
            "mx": mx,
            "spf": spf,
            "dmarc": dmarc,
        }
