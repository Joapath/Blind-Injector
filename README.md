# blind-finder

Framework extensible para pruebas autorizadas de inyección SQL ciega basada en booleanos.

blind-finder está orientado a escenarios de validación controlada, con un diseño modular y pruebas unitarias que no requieren acceso a red real. El proyecto permite evaluar si un punto de inyección se comporta como una condición booleana y extraer datos de forma gradual, según el tipo de detector y la estrategia de búsqueda configurada.

> Importante: este proyecto solo debe utilizarse contra sistemas para los que tengas autorización explícita.

## Alcance actual

La versión actual incluye:

- solicitudes GET y POST
- puntos de inyección en query string, cuerpo y cookies
- detectores de texto, longitud y código de estado
- modo de ataque Oracle conditional-error con texto, regex o código de estado
- estrategias de búsqueda por fuerza bruta y binaria
- modelos HTTP desacoplados de la librería de requests y pruebas sin acceso a red

Se excluyen intencionadamente técnicas basadas en tiempo, payloads de error no Oracle, concurrencia y evasión de WAF.

## Requisitos

- Python 3.11 o superior
- pip
- acceso a un endpoint autorizado para probar la herramienta

## Instalación

Desde la raíz del proyecto:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
# o instalación editable
pip install -e .
```

También puedes ejecutar la CLI directamente desde el código sin instalar el paquete:

```bash
python3 -m cli --help
```

## Uso rápido

### Ver ayuda

```bash
python3 -m cli --help
```

### Ejemplo básico con detector de texto

```bash
python3 -m cli \
  --url "https://example.com/filter" \
  --method GET \
  --parameter TrackingId \
  --location cookie \
  --cookie "session=TOKEN_SESION" \
  --cookie "TrackingId=VALOR_BASE" \
  --strategy binary \
  --attack-mode conditional-response \
  --detector text \
  --true-text "Welcome back" \
  --expression password \
  --max-length 20
```

### Ejemplo de Oracle conditional-error

Este modo requiere una señal explícita de error (texto, regex o código HTTP) y no asume que cualquier 5xx implica una condición verdadera:

```bash
python3 -m cli \
  --url "https://LAB_HOST/filter" \
  --parameter TrackingId \
  --location cookie \
  --cookie "TrackingId=BASE_VALUE" \
  --cookie "session=SESSION_VALUE" \
  --expression password \
  --attack-mode conditional-error \
  --error-regex "ORA-[0-9]+" \
  --max-length 20
```

## Parámetros principales

La CLI admite estos argumentos clave:

- `--url`: URL del objetivo
- `--method`: `GET` o `POST`
- `--parameter`: nombre del parámetro a inyectar
- `--location`: `query`, `body` o `cookie`
- `--query`, `--body`, `--cookie`, `--header`: datos de la petición base
- `--expression`: columna o expresión que se quiere extraer
- `--strategy`: `binary` o `brute`
- `--attack-mode`: `conditional-response` o `conditional-error`
- `--detector`: `text`, `length`, `status` o `error`
- `--charset`: conjunto de caracteres a probar
- `--max-length`: longitud máxima de extracción
- `--timeout`: timeout HTTP
- `--delay`: retardo entre peticiones
- `--proxy`: proxy HTTP/SOCKS si aplica
- `--insecure`: deshabilita verificación TLS
- `--verbose`: activa salida más detallada
- `--log-file`: ruta del archivo de log

## Modos de ataque

### conditional-response

Comprueba si la respuesta del servidor cambia ante una condición SQL verdadera/falsa. Requiere un estado observable claro, por ejemplo un texto de respuesta o un código de estado conocido.

### conditional-error

Usa una señal explícita de error para deducir la verdad de una condición SQL, por ejemplo:

- texto de error
- regex de error
- código de estado

Esto es útil para laboratorios o objetivos que exponen errores de base de datos de forma controlada.

## Estrategias de extracción

El proyecto soporta dos enfoques principales:

- `binary`: búsqueda binaria sobre el conjunto de caracteres
- `brute`: fuerza bruta secuencial

La estrategia seleccionada afecta la eficiencia del proceso de extracción, pero la semántica del detector sigue siendo la base de la decisión.

## Estructura del proyecto

```text
Blind-Injector/
├── cli/                  # interfaz de línea de comandos
├── config/               # construcción del grafo de dependencias
├── core/                 # motor principal y extractores
├── detection/            # detectores de respuesta
├── docs/                 # documentación técnica
├── exceptions/           # excepciones del proyecto
├── models/               # modelos de configuración y respuesta
├── payloads/             # construcción de payloads y condiciones
├── transport/            # cliente HTTP y abstracción del transporte
├── tests/                # pruebas unitarias
├── utils/                # utilidades varias
├── README.md             # documentación principal
├── pyproject.toml        # metadatos del paquete
├── requirements.txt      # dependencias del proyecto
└── cli/ejemplo-comando.txt
```

## Documentación técnica

El repositorio incluye documentación adicional en español:

- [Docs/architecture.md](Docs/architecture.md): arquitectura y flujo del sistema
- [Docs/Referencia_tecnica.md](Docs/Referencia_tecnica.md): referencia técnica del proyecto
- [Docs/Modulos_explicacion.md](Docs/Modulos_explicacion.md): explicación de módulos
- [Docs/Posibles_inconsistencias.md](Docs/Posibles_inconsistencias.md): limitaciones y observaciones de diseño

## Ejecutar tests

```bash
python3 -m unittest discover -s tests -v
```

## Recomendaciones de uso

- Usa la herramienta solo en entornos autorizados.
- No publiques cookies, tokens, payloads completos ni resultados extraídos en logs.
- Define una línea base de respuesta antes de lanzar la extracción.
- El modo `--verbose` aporta información útil para debug, pero el archivo de log es la fuente más detallada.
- Los códigos de estado o textos de error deben ser específicos y estables para evitar falsos positivos.

## Seguridad y límites

Este proyecto no debe emplearse para auditorías no autorizadas ni para pruebas contra sistemas ajenos. Los valores sensibles, las cookies de sesión y cualquier dato extraído deben manejarse con cuidado y no registrarse en ficheros de log si es posible.

El proyecto se concentra en inyección SQL ciega basada en booleanos y evita intencionadamente técnicas más avanzadas como delay-based attacks, bypasses de WAF o payloads no Oracle.

## Licencia

Consulta el archivo de metadatos del paquete y la configuración del repositorio para verificar la licencia aplicable.
