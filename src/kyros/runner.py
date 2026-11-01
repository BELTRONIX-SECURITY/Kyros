"""Ejecuta todos los servicios en paralelo y recoge los resultados."""

import asyncio

import httpx

from kyros import __version__
from kyros.models import Report, ServiceResult
from kyros.services import ALL_SERVICES
from kyros.services.base import Context, Service
from kyros.validate import split_email

USER_AGENT = f"kyros/{__version__}"


async def run_service(service: Service, ctx: Context) -> ServiceResult:
    if service.key_name and not ctx.keys.get(service.key_name):
        return ServiceResult(
            service.name, "skipped", error=f"falta la API key '{service.key_name}'"
        )
    try:
        data = await asyncio.wait_for(service.run(ctx), timeout=ctx.timeout)
        return ServiceResult(service.name, "ok", data=data)
    except asyncio.TimeoutError:
        return ServiceResult(service.name, "error", error="tiempo de espera agotado")
    except httpx.HTTPStatusError as exc:
        # No usamos str(exc): incluye la URL y podría filtrar claves.
        return ServiceResult(service.name, "error", error=f"HTTP {exc.response.status_code}")
    except httpx.RequestError as exc:
        return ServiceResult(service.name, "error", error=type(exc).__name__)
    except Exception as exc:  # noqa: BLE001 - un servicio nunca debe romper el resto
        return ServiceResult(service.name, "error", error=f"{type(exc).__name__}: {exc}")


async def scan(
    email: str,
    keys: dict[str, str],
    timeout: float = 15.0,
    services: list[Service] | None = None,
) -> Report:
    local, domain = split_email(email)
    selected = services if services is not None else [cls() for cls in ALL_SERVICES]

    async with httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT}, timeout=timeout, follow_redirects=True
    ) as client:
        ctx = Context(
            email=email.strip(),
            local=local,
            domain=domain,
            client=client,
            keys=keys,
            timeout=timeout,
        )
        results = await asyncio.gather(*(run_service(s, ctx) for s in selected))

    return Report(email=ctx.email, domain=domain, results=list(results))
