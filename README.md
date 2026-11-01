# Kyros

Herramienta OSINT automatizada para **correos electrónicos**, escrita en Python. Consulta varias fuentes en paralelo y devuelve un informe en terminal o en JSON.

> Este proyecto está escrito desde cero.

## Qué hace

| Servicio | Información | API key |
|---|---|---|
| DNS | MX, SPF y DMARC del dominio | No |
| ipapi.co | Ubicación y organización del servidor | No |
| Gravatar | Perfil público y cuentas verificadas | No |
| emailrep.io | Reputación, perfiles y filtraciones | Opcional |
| hunter.io | Correos relacionados del dominio | Sí |
| HaveIBeenPwned | Brechas de datos donde aparece el correo | Sí |

Los servicios sin API key configurada se omiten; un servicio que falle nunca rompe a los demás.

## Instalación

```bash
git clone https://github.com/TU_USUARIO/kyros.git
cd kyros
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Configuración

Copia `config.example.yaml` a `~/.kyros.yaml` y rellena las claves que tengas, o usa variables de entorno: `KYROS_HUNTER_KEY`, `KYROS_EMAILREP_KEY`, `KYROS_HIBP_KEY`.

## Uso

```bash
kyros ejemplo@dominio.com
kyros ejemplo@dominio.com -o informe.json
kyros ejemplo@dominio.com --json
kyros ejemplo@dominio.com --config ./config.yaml --timeout 20
```

## Docker

```bash
docker build -t kyros .
docker run --rm -e KYROS_HIBP_KEY=xxx kyros ejemplo@dominio.com
```

## Añadir un servicio nuevo

1. Crea `src/kyros/services/mi_servicio.py` con una clase que herede de `Service` e implemente `async def run(self, ctx)`.
2. Si necesita clave, define `key_name = "mi_servicio"` (y añádelo a `KNOWN_KEYS` en `config.py`).
3. Regístralo en `ALL_SERVICES` dentro de `services/__init__.py`.

## Tests

```bash
pytest
ruff check .
```

## Uso responsable

Usa esta herramienta solo sobre direcciones propias o con autorización expresa, y respetando los términos de cada servicio y la normativa de protección de datos aplicable (por ejemplo, el RGPD).

## Licencia

MIT. Sustituye `[Libardo Beltran]` en `LICENSE`.
