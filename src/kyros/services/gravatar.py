"""Perfil público de Gravatar asociado al correo (sin clave)."""

import hashlib
from typing import Any

from kyros.services.base import Context, Service


class Gravatar(Service):
    name = "Gravatar"

    async def run(self, ctx: Context) -> dict[str, Any]:
        digest = hashlib.sha256(ctx.email.strip().lower().encode()).hexdigest()
        resp = await ctx.client.get(f"https://api.gravatar.com/v3/profiles/{digest}")
        if resp.status_code == 404:
            return {"perfil": False}
        resp.raise_for_status()
        data = resp.json()
        return {
            "perfil": True,
            "nombre": data.get("display_name"),
            "url": data.get("profile_url"),
            "ubicacion": data.get("location"),
            "cuentas_verificadas": [
                {"servicio": a.get("service_label"), "url": a.get("url")}
                for a in data.get("verified_accounts", [])
            ],
        }
