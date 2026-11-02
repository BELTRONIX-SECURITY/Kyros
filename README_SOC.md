# Kyros SOC 0.6.0 — documentación técnica

Kyros SOC es una interfaz web y API FastAPI para triaje defensivo local. Mantiene la CLI OSINT original. Esta versión es un MVP para pruebas controladas, no un SIEM empresarial ni un sistema de detección automática.

## Despliegue actual en Render

El servicio existente `kyros-soc` está conectado al repositorio `troytechnology/Kyros`, rama `main`, con despliegue automático por commit.

- URL: https://kyros-soc.onrender.com
- Health check público: https://kyros-soc.onrender.com/api/health
- Panel de Render: https://dashboard.render.com/web/srv-dbjnksm7bikc7381f1mg
- Plan: Free, región Frankfurt.
- Comando de compilación: `pip install .`
- Comando de inicio: `uvicorn kyros.web:app --host 0.0.0.0 --port $PORT`
- Ruta de comprobación: `/api/health`

No es necesario crear otro Blueprint ni seleccionar una rama alternativa para continuar las pruebas de este servicio. Los commits en `main` activan el despliegue.

### Variables de entorno

Configura desde el panel de Render, sin publicar sus valores:

| Variable | Uso |
|---|---|
| `KYROS_ENV` | `production` |
| `KYROS_DB_PATH` | `/tmp/kyros_soc.sqlite3` |
| `KYROS_AUTH_USERNAME` | Usuario HTTP Basic |
| `KYROS_AUTH_PASSWORD` | Contraseña exclusiva de al menos 16 caracteres |
| `KYROS_AI_BASE_URL` | Opcional; endpoint compatible con OpenAI |
| `KYROS_AI_MODEL` | Opcional; modelo del proveedor |
| `KYROS_AI_API_KEY` | Opcional; secreto del proveedor |

La autenticación no se considera configurada si falta el usuario o la contraseña no alcanza la longitud mínima; la aplicación responde con error 503 en rutas protegidas. No compartas las credenciales en chats, capturas ni archivos del repositorio.

### Límites de Render Free

- El servicio puede suspenderse tras periodos de inactividad.
- El sistema de archivos es efímero. SQLite en `/tmp/kyros_soc.sqlite3` puede perderse al reiniciar, suspender o desplegar.
- No hay disco persistente ni copias de seguridad automáticas configuradas.
- Este entorno es exclusivamente para pruebas con datos ficticios. No almacenes muestras confidenciales, información personal ni datos SOC reales.
- No cambies el plan ni añadas recursos de pago para estas pruebas.

## Ejecución local

Requisitos: Python 3.10 o superior.

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

Configura credenciales de desarrollo:

Linux/macOS:
```bash
export KYROS_AUTH_USERNAME="soc-admin"
export KYROS_AUTH_PASSWORD="cambia-por-una-clave-de-prueba-de-16-caracteres"
kyros-web
```

Windows PowerShell:
```powershell
$env:KYROS_AUTH_USERNAME = "soc-admin"
$env:KYROS_AUTH_PASSWORD = "cambia-por-una-clave-de-prueba-de-16-caracteres"
kyros-web
```

Abre http://127.0.0.1:8000. En desarrollo, la API interactiva está en `/docs`. En producción, Swagger, ReDoc y OpenAPI están deshabilitados.

## Módulos implementados

- **Dashboard:** totales del historial, actividad de las últimas 24 horas y distribución de incidentes registrados.
- **IP Intelligence:** clasificación local IPv4/IPv6. Enriquecimiento geográfico/ASN opcional para IP públicas mediante ipapi.co y FreeIPAPI.
- **Domain Intelligence:** validación local y consultas DNS opcionales A, AAAA, MX, TXT y DMARC.
- **Email Intelligence:** validación de sintaxis y normalización local; no verifica existencia del buzón ni reputación.
- **File Intelligence:** límite de 10 MB; hashes SHA-256, SHA-1 y MD5; identificación estática de formatos y análisis estructural de Office Open XML.
- **Threat Intelligence:** catálogo local de IP, dominios, correos y SHA-256; importación CSV/XLSX; análisis de archivos y extracción de candidatos IOC desde formatos de texto compatibles.
- **Event Correlation:** registro manual de eventos y coincidencia exacta con el catálogo IOC.
- **Incident Center:** creación manual de casos y estados abierto, reconocido y cerrado.
- **Historial:** consultas de análisis y métricas almacenadas en SQLite.
- **Copiloto IA:** opcional; solo transmite el texto que el analista pega y autoriza expresamente.

## Formatos y límites de importación

### Catálogo IOC

Se admiten archivos CSV UTF-8 y Excel XLSX (primera hoja). Columnas obligatorias:

- `indicator_type`
- `indicator`

Columnas opcionales:

- `confidence` (0–100; valor predeterminado 50)
- `source`
- `description`

Tipos admitidos: `ip`, `domain`, `email`, `sha256`. Límite de 2 MB y 5000 filas. Los valores se validan antes de guardarse localmente. Las filas no válidas se notifican y no detienen el resto de la importación. Los archivos XLS antiguos no están soportados.

### Análisis de archivos y extracción IOC

El análisis acepta archivos no vacíos de hasta 10 MB. Calcula hashes e identifica tipo y estructura; no ejecuta archivos ni los envía a terceros.

La extracción de candidatos IOC se limita a archivos de texto UTF-8 con extensiones compatibles: `.txt`, `.log`, `.csv`, `.json`, `.xml`, `.yaml`, `.yml`, `.eml`, `.conf`, `.ini`, `.cfg`, `.out`. Se limita a 500 candidatos. No se importan automáticamente: cada candidato requiere revisión y aprobación manual.

Office Open XML se inspecciona estáticamente con límites de recursos: hasta 2000 entradas ZIP, 40 MB expandidos, 8 MB por entrada y ratio máximo de compresión 200:1 para entradas mayores de 1 MB. La presencia de macros, fórmulas o enlaces externos no demuestra que un documento sea malicioso.

YARA es opcional y necesita instalar el extra `kyros[yara]` y configurar `KYROS_YARA_RULES` con una ruta local de reglas. El repositorio no incluye un conjunto de reglas. ClamAV y sandbox no están integrados.

## Privacidad y seguridad

- La API y el dashboard requieren HTTP Basic; `/api/health` es público para la comprobación de Render.
- Las solicitudes de escritura requieren además la cabecera `X-Kyros-Request: 1`.
- Se aplican cabeceras de seguridad, incluida CSP y protección contra framing.
- Las consultas IP y DNS requieren consentimiento explícito. Solo se envía el indicador necesario al servicio correspondiente.
- No se transmiten archivos, historial, credenciales ni eventos a proveedores externos.
- El copiloto IA solo recibe el texto enviado manualmente tras marcar la casilla de consentimiento. No pegues secretos, tokens ni datos personales.
- El historial de archivos conserva hashes y metadatos, no los bytes ni el nombre original.
- La autenticación es compartida: no hay usuarios individuales, MFA ni SSO.
- No hay rate limiting de aplicación ni auditoría inmutable configurados en este MVP.

Geolocalización y ASN no son reputación. Un IOC válido, una coincidencia o un resultado de IA no son por sí solos prueba de un incidente.

## Pruebas automatizadas

```bash
ruff check .
pytest -q
```

GitHub Actions ejecuta los controles de calidad en los commits de `main`. La ejecución debe terminar en verde antes de considerar un cambio listo para desplegar.

## Guion de pruebas manuales en Render

Utiliza exclusivamente los siguientes datos de demostración y archivos de texto ficticios:

1. Abrir la URL de la aplicación y confirmar que solicita autenticación.
2. Abrir `/api/health` y comprobar que responde con estado `ok`.
3. En IP Intelligence, analizar `8.8.8.8` dejando desmarcada la consulta externa.
4. En Domain Intelligence, analizar `example.com` sin marcar consulta DNS.
5. En Email Intelligence, analizar `analyst@example.com`.
6. En Threat Intelligence, guardar un IOC de prueba y comprobar que aparece en el catálogo.
7. Registrar un evento con el mismo indicador y comprobar que aparece una coincidencia local.
8. Crear un incidente de prueba y cambiar su estado.
9. Subir un archivo TXT ficticio con un indicador de ejemplo; revisar candidatos y aprobar manualmente solo uno.
10. Comprobar el historial y el dashboard. Recordar que los datos pueden desaparecer al reiniciar o desplegar.

No habilites consultas externas ni el copiloto IA durante la primera ronda de pruebas. Una vez validados los flujos locales, cada integración externa debe probarse por separado y con consentimiento.

## Pendiente antes de producción

Persistencia y copias de seguridad verificadas, gestión individual de usuarios y MFA/SSO, rate limiting, auditoría, revisión integral de seguridad, pruebas de carga y monitorización. También faltan conectores SIEM/EDR, ingesta automática, reputación externa de IOC, ClamAV y sandbox aislada.

La futura portabilidad a un servidor propio se abordará en una fase separada. El Dockerfile actual está orientado a la CLI; el contenedor web y la persistencia en volumen deberán prepararse y probarse antes de migrar.
