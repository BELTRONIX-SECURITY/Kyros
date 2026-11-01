# Kyros SOC — primera fase web

Esta rama incorpora una primera interfaz web y API defensiva, manteniendo la CLI OSINT original.

## Requisitos
Python 3.10 o superior.

## Instalación y ejecución
En Linux/macOS:
    python -m venv .venv
    source .venv/bin/activate
En Windows PowerShell:
    python -m venv .venv
    .venv\Scripts\Activate.ps1

Instala y ejecuta:
    pip install -e ".[dev]"
    kyros-web

Abre http://127.0.0.1:8000. La documentación interactiva de la API está en http://127.0.0.1:8000/docs.

## Funciones incluidas
- Dashboard web adaptable.
- API FastAPI y endpoint de estado.
- Clasificación sintáctica de IPv4/IPv6 (pública, privada y especial).
- Validación y normalización IDNA de dominios.
- Triaje estático: hashes MD5/SHA1/SHA256 y firmas básicas de archivo.
- Límite de carga de 10 MB; el contenido del archivo se procesa en memoria y no se guarda.
- Historial local SQLite para indicadores, hashes y metadatos de análisis; no se conserva el contenido del archivo ni su nombre original.
- Consultas externas desactivadas; no se envían indicadores o archivos a terceros.
- Ruta de base de datos configurable con KYROS_DB_PATH; por defecto ~/.kyros/kyros_soc.sqlite3.

## Límites importantes
No se incorpora todavía reputación externa, DNS, YARA, ClamAV, sandbox, correlación SIEM, gestión de incidentes, autenticación multiusuario ni alertas en tiempo real. Un resultado unknown significa que no existe evidencia suficiente para asignar reputación. Una IP o dominio no confirma por sí solo un ataque activo.

La API escucha por defecto en 127.0.0.1. No la expongas a Internet ni a una red compartida sin añadir autenticación, autorización, TLS, controles de abuso y revisión de seguridad. La base de datos local contiene indicadores consultados, por lo que debe protegerse con los permisos del sistema operativo.

## Próximos incrementos
1. Motor de análisis estático ampliado con YARA/ClamAV, ejecutado en entorno aislado.
2. Fuentes opcionales de Threat Intelligence, habilitadas explícitamente y con controles de privacidad.
3. Ingesta y correlación de eventos Wazuh/SIEM.
4. Centro de incidentes, auditoría, roles y controles de acceso.
5. Endurecimiento, pruebas de integración y despliegue controlado.
