"""Reputación del correo y perfiles conocidos (emailrep.io). La clave es opcional."""

from typing import Any

from kyros.services.base import Context, Service


class EmailRep(Service):
    name = "emailrep.io"

    async def run(self, ctx: Context) -> dict[str, Any]:
        headers = {"Key": ctx.keys["emailrep"]} if ctx.keys.get("emailrep") else {}
        resp = await ctx.client.get(f"https://emailrep.io/{ctx.email}", headers=headers)
        resp.raise_for_status()
        data = resp.json()
        details = data.get("details", {})
        return {
            "reputacion": data.get("reputation"),
            "sospechoso": data.get("suspicious"),
            "referencias": data.get("references"),
            "filtrado_en_brechas": details.get("data_breach"),
            "credenciales_filtradas": details.get("credentials_leaked"),
            "actividad_maliciosa": details.get("malicious_activity"),
            "desechable": details.get("disposable"),
            "perfiles": details.get("profiles", []),
        }
