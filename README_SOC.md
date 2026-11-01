# Kyros SOC 0.6.0 — dashboard y centro de incidentes

Esta rama incorpora un dashboard SOC, API defensiva, métricas reales, historial y un centro de gestión manual de incidentes, manteniendo la CLI OSINT original.

## Ejecución local

Requisitos: Python 3.10 o superior.

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell: .venv\\Scripts\\Activate.ps1
pip install -e ".[dev]"
```

Configura credenciales antes de iniciar la aplicación. La contraseña debe tener al menos 16 caracteres.

Linux/macOS:
```bash
export KYROS_AUTH_USERNAME="admin"
export KYROS_AUTH_PASSWORD="cambia-esta-por-una-clave-larga"
kyros-web
```

Windows PowerShell:
```powershell
$env:KYROS_AUTH_USERNAME = "admin"
$env:KYROS_AUTH_PASSWORD = "cambia-esta-por-una-clave-larga"
kyros-web
```

Abre http://127.0.0.1:8000. El navegador solicitará autenticación HTTP Basic. En desarrollo, la documentación está en /docs.

## Despliegue de prueba gratuito en Render

Esta rama está preparada para una **prueba con el plan Free** de Render. No incluye disco persistente ni servicios de pago.

1. En Render, crea un Blueprint y selecciona este repositorio y la rama `security/free-deploy`.
2. Render leerá `render.yaml`. Configura `KYROS_AUTH_USERNAME` y `KYROS_AUTH_PASSWORD` como variables secretas. La contraseña debe tener al menos 16 caracteres; utiliza una contraseña aleatoria y exclusiva.
3. Revisa que el servicio figure con plan **Free** y que no se añadan discos ni otros recursos de pago antes de confirmar.
4. Despliega y prueba la URL HTTPS. El navegador debe solicitar credenciales antes de mostrar el dashboard.

### Limitaciones del plan gratuito

- El servicio puede entrar en suspensión tras un periodo de inactividad y tardar en responder cuando se reactive.
- El sistema de archivos es efímero: la base SQLite se guarda en `/tmp/kyros_soc.sqlite3` y el historial puede desaparecer al reiniciar, suspender o volver a desplegar el servicio.
- El plan gratuito tiene límites de uso y recursos definidos por Render, que pueden cambiar.
- Esta configuración es para demostración y validación inicial, no para producción ni para almacenar información importante.

No introduzcas datos de pago para esta configuración. Si Render muestra un coste o exige cambiar a un plan de pago, detente y revisa la pantalla antes de continuar.

## Módulos disponibles en 0.5.0

- Resumen general: contadores de análisis, actividad de las últimas 24 horas y distribución por tipo/severidad.
- IP Intelligence: clasificación local IPv4/IPv6 y enriquecimiento geográfico/ASN opt-in para IP públicas.
- Domain Intelligence: validación local del formato y consultas DNS A, AAAA, MX, TXT y _dmarc únicamente con consentimiento explícito. No incluye reputación ni DKIM.
- Email Intelligence: validación local de sintaxis y normalización del dominio, sin consultar ni transmitir la dirección.
- Threat Intelligence: catálogo IOC local para IP, dominios, correos y hashes SHA-256, con fuente y confianza documentadas.
- Event Correlation: registro manual de eventos y coincidencia exacta contra el catálogo IOC local; los resultados son pistas, no incidentes confirmados.
- File Intelligence: tamaño, tipo por firma y hashes SHA-256/SHA-1/MD5; límite de 10 MB; sin ejecución ni envío externo.
- Incident Center: creación manual de casos, severidad y estados abierto/reconocido/cerrado.
- Historial: consulta de análisis y métricas sobre SQLite.
- Estado e integraciones: capacidades disponibles y pendientes.

Los incidentes son registros manuales; no se generan detecciones automáticas ni se declara un ataque activo sin telemetría correlacionada.

## Seguridad y fuentes externas

- Autenticación HTTP Basic obligatoria en dashboard y endpoints API.
- La aplicación falla de forma cerrada (503) si las credenciales no están configuradas o la contraseña tiene menos de 16 caracteres.
- Comparación de credenciales con comparación de tiempo constante.
- Cabeceras de seguridad y documentación interactiva deshabilitada en producción.
- Límite de carga de 10 MB; los archivos se procesan en memoria, no se ejecutan ni se envían a terceros.
- El historial conserva hashes y metadatos, no el contenido del archivo ni su nombre original.
- Las consultas externas de IP requieren marcar expresamente la casilla de consentimiento. Por defecto siguen desactivadas.
- Si se autoriza la consulta, solo se envía la IP pública indicada a ipapi.co y FreeIPAPI para obtener datos geográficos y ASN. Las IP privadas y especiales no se envían.
- Los proveedores externos reciben la IP consultada y pueden procesar solicitudes conforme a sus propias políticas, condiciones y límites. No se envían archivos, credenciales ni datos del historial.
- Geolocalización y ASN no equivalen a reputación ni demuestran actividad maliciosa. La puntuación de riesgo permanece sin determinar.

Documentación de proveedores:
- ipapi.co: https://ipapi.co/api/
- FreeIPAPI: https://app.freeipapi.com/docs/api-reference/get-ip-info

## Límites y medidas adicionales antes de usar con datos reales

HTTP Basic protege el acceso solo cuando se utiliza sobre HTTPS. Para una plataforma expuesta a Internet con varios usuarios, añade un proveedor de identidad/SSO, limitación de intentos en el perímetro, gestión de usuarios y auditoría. No reutilices contraseñas personales. La autenticación HTTP Basic del prototipo no ofrece cuentas individuales, MFA ni cierre de sesión centralizado.

Esta versión todavía no incorpora reputación de amenazas, listas de abuso, DNS, YARA, ClamAV, sandbox, correlación SIEM, gestión de incidentes ni alertas en tiempo real. No subas muestras confidenciales ni datos personales hasta completar una revisión de seguridad y pruebas de despliegue. Un indicador válido o desconocido no demuestra por sí solo un ataque activo.
