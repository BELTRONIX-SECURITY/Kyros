# Kyros SOC — primera fase web

Esta rama incorpora una primera interfaz web y API defensiva, manteniendo la CLI OSINT original.

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

## Seguridad incluida en esta fase

- Autenticación HTTP Basic obligatoria en dashboard y endpoints API.
- La aplicación falla de forma cerrada (503) si las credenciales no están configuradas o la contraseña tiene menos de 16 caracteres.
- Comparación de credenciales con comparación de tiempo constante.
- Cabeceras de seguridad: nosniff, frame deny, referrer policy, permissions policy y HSTS en HTTPS.
- Documentación interactiva y OpenAPI deshabilitados en producción.
- Límite de carga de 10 MB; el archivo se procesa en memoria y no se guarda.
- Historial SQLite conserva indicadores, hashes y metadatos, no el contenido del archivo ni su nombre original.
- Consultas externas desactivadas: no se envían indicadores o archivos a terceros.

## Límites y medidas adicionales antes de usar con datos reales

HTTP Basic protege el acceso solo cuando se utiliza sobre HTTPS. Para una plataforma expuesta a Internet con varios usuarios, añade un proveedor de identidad/SSO, limitación de intentos en el perímetro, gestión de usuarios y auditoría. No reutilices contraseñas personales. La autenticación HTTP Basic del prototipo no ofrece cuentas individuales, MFA ni cierre de sesión centralizado.

Esta versión no incorpora todavía reputación externa, DNS, YARA, ClamAV, sandbox, correlación SIEM, gestión de incidentes ni alertas en tiempo real. No subas muestras confidenciales ni datos personales hasta completar una revisión de seguridad y pruebas de despliegue. Un indicador válido o desconocido no demuestra por sí solo un ataque activo.
