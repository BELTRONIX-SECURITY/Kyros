# Kyros SOC

**Kyros** es una plataforma de análisis defensivo y apoyo a operaciones SOC, desarrollada en Python. Combina una CLI OSINT con una interfaz web FastAPI para análisis local de indicadores, triaje estático de archivos, catálogo IOC, correlación manual y gestión de incidentes.

> Estado: MVP 0.6.0 desplegado en Render Free para pruebas controladas. No es una plataforma SIEM de producción ni sustituye a un EDR, antivirus o sandbox.

## Funcionalidades actuales

| Módulo | Capacidades |
|---|---|
| Dashboard | Métricas del historial y casos registrados |
| IP Intelligence | Clasificación IPv4/IPv6 local; enriquecimiento geográfico/ASN opcional y con consentimiento |
| Domain Intelligence | Validación local; consultas DNS A, AAAA, MX, TXT y DMARC opcionales |
| Email Intelligence | Validación y normalización local; no consulta reputación |
| File Intelligence | Hashes MD5/SHA-1/SHA-256, identificación estática y revisión estructural de documentos Office |
| Threat Intelligence | Catálogo IOC local, importación CSV/XLSX y extracción de candidatos desde texto |
| Event Correlation | Registro manual y coincidencia exacta contra el catálogo IOC local |
| Incident Center | Creación y seguimiento manual de casos |
| Copiloto IA | Opcional; requiere configuración y consentimiento explícito para enviar el texto introducido |
| Historial | Registros locales de análisis y actividad |

Los indicadores extraídos de archivos son candidatos que requieren revisión humana. Las coincidencias IOC no confirman incidentes. No existen todavía conectores SIEM/EDR activos ni detección automática en tiempo real.

## Despliegue de pruebas

- Aplicación: https://kyros-soc.onrender.com
- Repositorio: https://github.com/troytechnology/Kyros
- Rama desplegada: `main`
- Servicio: Render Web Service, plan Free, región Frankfurt.
- Health check: `/api/health`

Render está configurado para desplegar automáticamente los nuevos commits de `main`. La interfaz y los endpoints protegidos requieren HTTP Basic. Las credenciales se configuran como variables del servicio en Render; nunca deben incluirse en el repositorio.

### Limitaciones del entorno gratuito

La base SQLite se guarda en `/tmp/kyros_soc.sqlite3`. El almacenamiento de Render Free es efímero: el historial, los IOC y los incidentes pueden perderse al reiniciar o desplegar. No se debe utilizar para datos operativos importantes ni como almacenamiento de producción.

No se ha contratado disco persistente, base de datos ni otro recurso de pago. No añadas recursos ni actives facturación para ejecutar estas pruebas.

## Prueba local

Requisitos: Python 3.10 o superior.

```bash
git clone https://github.com/troytechnology/Kyros.git
cd Kyros
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

Configura credenciales de prueba antes de iniciar la interfaz. La contraseña debe tener al menos 16 caracteres.

Linux/macOS:
```bash
export KYROS_AUTH_USERNAME="soc-admin"
export KYROS_AUTH_PASSWORD="sustituye-por-una-clave-de-prueba-larga"
kyros-web
```

Windows PowerShell:
```powershell
$env:KYROS_AUTH_USERNAME = "soc-admin"
$env:KYROS_AUTH_PASSWORD = "sustituye-por-una-clave-de-prueba-larga"
kyros-web
```

Abre http://127.0.0.1:8000. La documentación interactiva de la API está disponible en `/docs` únicamente en entorno de desarrollo.

## Pruebas automatizadas

```bash
ruff check .
pytest -q
```

GitHub Actions ejecuta lint y pruebas para las versiones de Python configuradas en los workflows.

## Privacidad y seguridad

- El análisis de archivos es estático: Kyros no ejecuta los archivos ni los envía automáticamente a terceros.
- El historial de archivos conserva hashes y metadatos, no el contenido ni el nombre original.
- Las consultas IP y DNS externas están desactivadas por defecto y requieren una acción expresa.
- El copiloto IA es opcional y solo recibe el texto que el analista pega y autoriza enviar.
- La autenticación actual es HTTP Basic compartida; no ofrece cuentas individuales, MFA ni SSO.
- No se deben introducir credenciales, tokens, datos personales ni muestras confidenciales en el entorno público de pruebas.

Consulta [README_SOC.md](README_SOC.md) para el alcance detallado, configuración, formatos de importación y limitaciones.

## CLI OSINT

La CLI original permite consultar fuentes OSINT para direcciones de correo. Algunas integraciones requieren claves API propias y pueden transmitir la dirección consultada al proveedor correspondiente. Revisa sus condiciones y la configuración antes de utilizarlas.

```bash
kyros ejemplo@dominio.com
kyros ejemplo@dominio.com --json
kyros ejemplo@dominio.com -o informe.json
```

## Docker

El Dockerfile actual mantiene el punto de entrada de la CLI. La ejecución web en contenedor y la persistencia de SQLite se prepararán como parte de la portabilidad futura al servidor propio; no forman parte del despliegue actual de Render.

## Uso responsable y licencia

Utiliza Kyros únicamente sobre activos propios o con autorización. Respeta las condiciones de los proveedores y la normativa aplicable, incluido el RGPD.

Licencia MIT. Consulta [LICENSE](LICENSE).
