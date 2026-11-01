"""Brechas de datos donde aparece el correo (HaveIBeenPwned)."""

from typing import Any
from urllib.parse import quote

from kyros.services.base import Context, Service


class HaveIBeenPwned(Service):
    name = "HaveIBeenPwned"
    key_name = "hibp"

    async def run(self, ctx: Context) -> dict[str, Any]:
        resp = await ctx.client.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(ctx.email)}",
            params={"truncateResponse": "false"},
            headers={"hibp-api-key": ctx.keys["hibp"]},
        )
        if resp.status_code == 404:
            return {"brechas": []}
        resp.raise_for_status()
        return {
            "brechas": [
                {
                    "nombre": b.get("Name"),
                    "fecha": b.get("BreachDate"),
                    "datos_expuestos": b.get("DataClasses"),
                }
                for b in resp.json()
            ]
        }
