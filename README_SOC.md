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

## Despliegue público protegido en Render

Existe un archivo `render.yaml` para desplegar desde la rama `security/private-deploy`.

1. Crea una cuenta Render y conecta GitHub.
2. En Render, crea un Blueprint y selecciona este repositorio y la rama `security/private-deploy`.
3. Render detectará `render.yaml`. Configura `KYROS_AUTH_USERNAME` y `KYROS_AUTH_PASSWORD` como secretos. Usa una contraseña aleatoria de al menos 20 caracteres; no la guardes en GitHub.
4. Despliega el servicio y prueba la URL HTTPS. El navegador debe solicitar credenciales antes de mostrar el dashboard.
5. Mantén el disco persistente asociado al servicio para conservar el historial SQLite.

El servicio usa HTTPS administrado por Render, escucha en 0.0.0.0 mediante el comando de inicio y guarda la base SQLite en /var/data. El plan configurado requiere un servicio con disco persistente; revisa el precio vigente de Render antes de crear recursos.

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

HTTP Basic protege el acceso solo cuando se utiliza sobre HTTPS. Para una plataforma expuesta a Internet con varios usuarios, añade un proveedor de identidad/SSO como Cloudflare Access, limitación de intentos en el perímetro, gestión de usuarios y auditoría. No reutilices contraseñas personales. La autenticación HTTP Basic del prototipo no ofrece cuentas individuales, MFA ni cierre de sesión centralizado.

Esta versión no incorpora todavía reputación externa, DNS, YARA, ClamAV, sandbox, correlación SIEM, gestión de incidentes ni alertas en tiempo real. No subas muestras confidenciales ni datos personales hasta completar una revisión de seguridad y pruebas de despliegue. Un indicador válido o desconocido no demuestra por sí solo un ataque activo.
