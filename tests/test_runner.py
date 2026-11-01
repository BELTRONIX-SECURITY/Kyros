import asyncio

from kyros.runner import scan
from kyros.services.base import Service


class Bueno(Service):
    name = "bueno"

    async def run(self, ctx):
        return {"dominio": ctx.domain}


class Roto(Service):
    name = "roto"

    async def run(self, ctx):
        raise RuntimeError("fallo simulado")


class ConClave(Service):
    name = "con-clave"
    key_name = "secreta"

    async def run(self, ctx):
        return {}


def test_un_servicio_roto_no_afecta_a_los_demas():
    report = asyncio.run(scan("a@example.com", {}, services=[Bueno(), Roto(), ConClave()]))
    estados = {r.name: r.status for r in report.results}
    assert estados == {"bueno": "ok", "roto": "error", "con-clave": "skipped"}
    assert report.results[0].data == {"dominio": "example.com"}
