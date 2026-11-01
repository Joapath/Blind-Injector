# blind-finder

Framework extensible para pruebas autorizadas de inyección SQL ciega: booleana, temporal, error condicional (Oracle) y visible-error (Postgres), con paralelismo, rate limiting, calibración automática de timing y resume de extracciones interrumpidas.

blind-finder está orientado a escenarios de validación controlada, con un diseño modular por capas (`models → transport → payloads → detection → core → config → cli`) y pruebas unitarias que no requieren acceso a red real. Evalúa si un punto de inyección se comporta como una condición booleana, temporal o de error, y extrae datos de forma gradual según la técnica, detector y estrategia de búsqueda configurada.

> **Importante:** este proyecto solo debe utilizarse contra sistemas para los que tengas autorización explícita.

## Índice

- [Alcance actual](#alcance-actual)
- [Requisitos e instalación](#requisitos-e-instalación)
- [Uso rápido](#uso-rápido)
- [Referencia de flags](#referencia-de-flags)
- [Técnicas y modos de ataque](#técnicas-y-modos-de-ataque)
- [Auto-detección (`--technique auto`)](#auto-detección---technique-auto)
- [Probar todos los parámetros](#probar-todos-los-parámetros-sin-saber-cuál-es-el-inyectable)
- [Importar request cruda (`-r`, como sqlmap)](#importar-request-cruda--r-como-sqlmap)
- [Catálogo de enumeración (`--enum`)](#catálogo-de-enumeración---enum)
- [Estrategias de extracción](#estrategias-de-extracción)
- [Calibración automática de timing](#calibración-automática-de-timing)
- [Extracción paralela y rate limiting](#extracción-paralela-y-rate-limiting)
- [Evasión de WAF: tamper y headers](#evasión-de-waf-tamper-y-headers)
- [Checkpoint y resume](#checkpoint-y-resume)
- [Reporte exportable](#reporte-exportable)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Documentación técnica](#documentación-técnica)
- [Tests](#tests)
- [Seguridad y límites](#seguridad-y-límites)
- [Licencia](#licencia)

## Alcance actual

- Solicitudes GET y POST; puntos de inyección en query string, cuerpo, cookies y headers.
- Detectores de texto, longitud, código de estado, error y timing.
- Técnica **booleana** (por defecto), **temporal** (sleep controlado para MySQL/Postgres, con calibración automática opcional) y **visible-error** (lectura directa del valor desde un error de Postgres).
- **Auto-detección** (`--technique auto`): sondea el punto de inyección y elige técnica/detector solo, con `confidence` explícita — nunca adivina en silencio.
- Modo de ataque Oracle conditional-error con texto, regex o código de estado.
- Estrategias de búsqueda por fuerza bruta y binaria.
- Extracción **paralela entre expresiones** (`--threads`) con **rate limiting** configurable (`--rate-limit`).
- **Evasión de WAF**: tampers de payload manuales tipo `sqlmap --tamper` (`--tamper`, `--tamper-profile`) y mutación de headers por request (`--random-agent`, `--random-xff`).
- **Checkpoint y resume** de extracciones interrumpidas (`--resume`, `--checkpoint-dir`).
- Modelos HTTP desacoplados de la librería de requests; toda la suite corre sin acceso a red.

Se excluyen intencionadamente: payloads de error no Oracle/Postgres, detección automática de bloqueo de WAF con reintento en cadena (la evasión es manual por ahora), timing auto-detectado para mssql/oracle, y paralelismo *dentro* de una misma expresión (el paralelismo actual es solo entre expresiones distintas). Ver el roadmap en `Docs-Claude/` para lo que sigue.

## Requisitos e instalación

- Python 3.11 o superior, pip, y acceso a un endpoint autorizado para probar la herramienta.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
# o instalación editable
pip install -e .
```

También podés ejecutar la CLI directamente desde el código sin instalar el paquete:

```bash
python3 -m cli --help
```

## Uso rápido

### Detector de texto (booleana, por defecto)

```bash
python3 -m cli \
  --url "https://example.com/filter" \
  --parameter TrackingId --location cookie \
  --cookie "session=TOKEN_SESION" --cookie "TrackingId=VALOR_BASE" \
  --strategy binary --detector text --true-text "Welcome back" \
  --expression password --max-length 20
```

### Oracle conditional-error

Requiere una señal explícita de error (texto, regex o código HTTP); un 5xx genérico nunca se trata como verdadero automáticamente.

```bash
python3 -m cli \
  --url "https://LAB_HOST/filter" \
  --parameter TrackingId --location cookie \
  --cookie "TrackingId=BASE_VALUE" --cookie "session=SESSION_VALUE" \
  --expression password \
  --attack-mode conditional-error --error-regex "ORA-[0-9]+" \
  --max-length 20
```

### Técnica temporal, con calibración automática

```bash
python3 -m cli \
  --url "https://example.test/filter" \
  --parameter TrackingId --location cookie \
  --cookie "TrackingId=BASE_VALUE" --cookie "session=SESSION_VALUE" \
  --strategy binary --technique time --dialect mysql \
  --sleep-seconds 3.0 --timing-threshold 2.0 \
  --auto-calibrate --calibration-samples 5 \
  --expression password --max-length 20
```

### Auto-detección, sin saber de antemano la técnica

```bash
python3 -m cli \
  --url "https://example.test/filter" \
  --parameter tracking --query "tracking=base" \
  --technique auto \
  --expression password --max-length 20
```

Imprime siempre lo que detectó (`[fingerprint] parameter=... location=... technique=... detector=...
dialect=... confidence=...`) antes de extraer nada, y si no encuentra una señal confiable
(`confidence=none`) falla con un mensaje claro en vez de adivinar. El `auto` también **sondea el
dialecto** del motor cuando el oráculo es booleano (postgres/mysql/oracle), así `--enum` no necesita
`--dialect` a mano; si no logra determinarlo deja `dialect=None` sin inventarlo.

### Probar todos los parámetros (sin saber cuál es el inyectable)

Con `--technique auto` y **sin** `--parameter` ni marcador `*`, la herramienta prueba cada parámetro de
query, cada cookie y cada campo de body, uno por uno, y se queda con el primero que exponga un oráculo:

```bash
python3 -m cli -r burp-request.txt --technique auto --enum tables
```

```
[probe] parameter=category location=query -> no oracle
[probe] parameter=TrackingId location=cookie -> boolean/text (confidence=confirmed)
```

Si ningún parámetro responde como oráculo, falla listando los que probó. Se detiene en el primero con
señal (no busca "el mejor"); si querés apuntar a uno puntual, pasá `--parameter`/`--location` o marcá
con `*`. Nota: `--enum` necesita conocer el dialecto — si el parámetro elegido no permite detectarlo,
pasá `--dialect` explícito.

### Importar request cruda (`-r`, como sqlmap)

En vez de desglosar `--cookie`/`--header`/`--query`/`--body`/`--parameter`/`--location` a mano a partir
de una request de Burp, guardá la request tal cual ("Copy to file" o "Save item") y marcá el punto de
inyección con un `*` al final del valor de un parámetro de query, cookie o body — igual que `sqlmap -r`:

```
GET /filter?category=Gifts HTTP/2
Host: example.test
Cookie: TrackingId=abc123*; session=xyz
```

```bash
python3 -m cli \
  --request-file burp-request.txt \
  --technique auto \
  --expression "(SELECT password FROM users WHERE username='administrator')" \
  --max-length 20
```

La herramienta parsea método, URL, headers, cookies, query y body del archivo, y avisa qué detectó:

```
[request-file] auto-detected injection point: parameter=TrackingId location=cookie
```

Combinado con `--technique auto` (arriba), este comando reemplaza una invocación manual con ~10 flags
de transporte/inyección por desglosar. Notas:

- El marcador `*` tiene que ir al **final** del valor (no a mitad, no en headers, no en el path) — si
  aparece en más de un lugar, o en una posición no soportada, la herramienta falla con un mensaje
  explícito en vez de adivinar cuál usar.
- `--request-file` no se puede combinar con `--url`/`--cookie`/`--header`/`--query`/`--body`/`--method`
  (la request del archivo es la única fuente de esos datos).
- Por defecto construye `http://`; pasá `--force-ssl` para `https://` (las requests crudas no llevan
  esquema).
- Si el archivo no tiene ningún `*`, seguís pudiendo pasar `--parameter`/`--location` a mano como
  siempre — útil para apuntar a un parámetro distinto del marcado, o si no marcaste ninguno.
- Body solo soporta `application/x-www-form-urlencoded` por ahora (igual límite que `--body KEY=VALUE`
  manual); JSON/multipart no están soportados todavía.

### Catálogo de enumeración (`--enum`)

Para preguntas de reconocimiento genéricas no hace falta escribir la subquery a mano: `--enum KIND`
(repetible) arma la query estructural correcta según `--dialect` y la extrae como una expresión más.

```bash
python3 -m cli -r burp-request.txt --technique auto --enum tables
python3 -m cli -r burp-request.txt --technique auto --enum columns --table users
```

Antes de correr imprime lo que construyó (nunca asume en silencio):

```
[enum] tables: (SELECT string_agg(table_name, ',') FROM information_schema.tables WHERE table_schema='public')
```

| KIND | qué extrae |
| --- | --- |
| `version` | versión del motor de base de datos |
| `current-user` | usuario de base de datos actual |
| `databases` | bases/esquemas visibles (en Oracle, usuarios/esquemas) |
| `tables` | tablas del esquema actual |
| `columns` | columnas de la tabla indicada con `--table` (default `users`) |

Cada `KIND` de lista (`databases`/`tables`/`columns`) concatena sus filas en un solo valor separado por
comas, así se extrae igual que cualquier otra expresión. Notas:

- Soporta los tres dialectos de `--dialect`: `mysql`, `postgres`, `oracle`.
- Los kinds de lista devuelven identificadores separados por comas, que el `--charset` por defecto
  (`a-z0-9`) no puede representar. Si no pasaste un `--charset` propio, la herramienta lo extiende sola
  con `,`, `_` y mayúsculas y lo avisa (`[enum] extended charset for list output with: ...`); pasá un
  `--charset` explícito si querés controlarlo vos.
- `--enum columns` usa `--table` (si no lo pasás, cae al default `users`); en Oracle el nombre de tabla
  se normaliza a mayúsculas automáticamente (así los guarda el diccionario de datos).
- Para leer **datos** que dependen del esquema (ej. la contraseña de un usuario) seguí usando
  `--expression` libre: eso no se cataloga porque tabla/columna varían por target.
- Las funciones de agregación tienen límites de longitud (`group_concat_max_len` en MySQL, ~4000 bytes
  de `LISTAGG` en Oracle): listas muy largas pueden venir truncadas.

### Con evasión de WAF (tamper + headers)

```bash
python3 -m cli \
  --url "https://example.test/filter" \
  --parameter TrackingId --location cookie \
  --cookie "TrackingId=BASE_VALUE" --cookie "session=SESSION_VALUE" \
  --detector text --true-text "Welcome back" \
  --tamper-profile cloudflare --random-agent --random-xff \
  --expression password --max-length 20
```

### Visible-error (Postgres)

Lee el valor directamente del cuerpo del error en lugar de inferirlo carácter por carácter: un solo request por expresión.

```bash
python3 -m cli \
  --url "https://LAB_HOST/filter" \
  --parameter TrackingId --location cookie --injection-mode replace \
  --cookie "TrackingId=BASE_VALUE" \
  --technique visible-error --attack-mode visible-error --dialect postgres --detector error \
  --expression password
```

### Varias columnas en paralelo, con rate limit y resume

Extrae `username` y `password_hash` a la vez (una instancia de extractor por expresión), sin superar 10 req/s, guardando progreso para poder retomar si algo se corta:

```bash
python3 -m cli \
  --url "https://example.com/filter" \
  --parameter TrackingId --location cookie \
  --cookie "TrackingId=BASE_VALUE" --cookie "session=SESSION_VALUE" \
  --detector text --true-text "Welcome back" \
  --expression username --expression password_hash \
  --threads 2 --rate-limit 10 \
  --max-length 64
```

Si se corta (`Ctrl+C`, error de red, lo que sea), la consola imprime el identificador de checkpoint. Repetir el mismo comando agregando `--resume` continúa desde la última posición confirmada de cada expresión.

## Referencia de flags

### General

| Flag | Descripción |
| --- | --- |
| `--verbose` | salida de consola detallada (progreso por posición) |
| `--log-file PATH` | log detallado a archivo (default `logs/log.log`) |
| `--resume` | reanuda desde un checkpoint previo si la configuración es idéntica |
| `--checkpoint-dir PATH` | directorio de checkpoints (default `~/.blind-finder/checkpoints`) |
| `--report-file PATH` | escribe un resumen de la corrida en PATH al terminar con éxito |
| `--report-format` | `json` (default) o `csv` |

### Target e inyección

| Flag | Descripción |
| --- | --- |
| `--url` | URL del objetivo (requerido, salvo que se use `--request-file`) |
| `-r`, `--request-file PATH` | request HTTP cruda (estilo Burp); marcador `*` autodetecta parámetro/ubicación; no combinable con `--url`/`--cookie`/`--header`/`--query`/`--body`/`--method` |
| `--force-ssl` | con `--request-file`, construye `https://` en vez de `http://` |
| `--method` | `GET` o `POST` (default `GET`) |
| `--parameter` | nombre del parámetro a inyectar (requerido, salvo marcador `*` en `--request-file`, o `--technique auto` que prueba todos) |
| `--location` | `query`, `body` o `cookie` (default `query`) |
| `--injection-mode` | `append` o `replace` (default `append`) |

### Datos de la petición y transporte

| Flag | Descripción |
| --- | --- |
| `--query`, `--body`, `--cookie`, `--header` | `KEY=VALUE`, repetibles |
| `--proxy` | proxy HTTP/SOCKS |
| `--timeout` | timeout HTTP en segundos (default `10.0`) |
| `--allow-redirects` | sigue redirecciones HTTP |
| `--max-retries` / `--retry-backoff` | reintentos para métodos seguros (default `0` / `0.0`) |
| `--insecure` | deshabilita verificación TLS |
| `--rate-limit` | requests/segundo máximos, compartido entre workers |

### Evasión de WAF

| Flag | Descripción |
| --- | --- |
| `--tamper` | nombres de tamper separados por coma, aplicados a cada payload |
| `--tamper-profile` | combinación heurística con nombre (`generic-waf`, `cloudflare`, `modsecurity`) |
| `--random-agent` | rota el User-Agent en cada request |
| `--random-xff` | randomiza X-Forwarded-For/X-Originating-IP/X-Real-IP/X-Client-IP en cada request |

### Extracción

| Flag | Descripción |
| --- | --- |
| `--expression` | expresión SQL a extraer; repetible (default: `--column`) |
| `--enum` | query de enumeración enlatada (`version`, `current-user`, `databases`, `tables`, `columns`); repetible; se arma según `--dialect`; `columns` usa `--table` |
| `--strategy` | `binary` o `brute` (default `binary`) |
| `--charset` | conjunto de caracteres candidatos |
| `--max-length` | longitud máxima a extraer (default `100`) |
| `--delay` | retardo entre requests (default `0.0`) |
| `--threads` | workers en paralelo entre expresiones distintas (default `1`; no soportado con `--technique time`) |

### Técnica y base de datos

| Flag | Descripción |
| --- | --- |
| `--technique` | `boolean`, `time`, `visible-error` o `auto` (default `boolean`) |
| `--attack-mode` | `conditional-response`, `conditional-error` o `visible-error` |
| `--dialect` | `oracle`, `mysql` o `postgres` (default `oracle`; con `--technique auto` se sondea solo; `time` acepta `mysql`/`postgres`) |
| `--table`, `--column`, `--user-column`, `--username` | usados por `conditional-error` (Oracle) |
| `--sleep-seconds` / `--timing-threshold` | requeridos por `technique=time` |
| `--auto-calibrate` | mide latencia real antes del ataque temporal |
| `--calibration-samples` | requests para calibrar (default `5`) |
| `--calibration-tolerance-factor` | multiplica el jitter medido para la tolerancia (default `3.0`) |

### Detección de respuesta

| Flag | Descripción |
| --- | --- |
| `--detector` | `text`, `length`, `status`, `error` o `timing` |
| `--true-text` | texto que identifica una respuesta positiva |
| `--expected-length` / `--expected-status` | para los detectores `length` / `status` |
| `--error-text` / `--error-regex` / `--error-status` | para `conditional-error` |
| `--error-value-regex` | para `visible-error`; debe tener un grupo nombrado `value` |
| `--timing-baseline` / `--timing-tolerance` | override manual si no se usa `--auto-calibrate` |

Ejecutá `python3 -m cli --help` para la lista completa con los valores por defecto exactos.

## Técnicas y modos de ataque

**`conditional-response`** comprueba si la respuesta cambia ante una condición SQL verdadera/falsa (texto, código o longitud). Es el modo por defecto.

**`conditional-error`** usa una señal explícita de error (texto, regex o código de estado) para deducir la verdad de la condición. Útil para laboratorios u objetivos que exponen errores de base de datos de forma controlada.

**`technique=boolean`** (default) infiere por señal booleana observable.

**`technique=time`** infiere por latencia. Requiere `--dialect mysql` o `--dialect postgres`, `--sleep-seconds` y `--timing-threshold`; los detectores booleanos se rechazan explícitamente en estas ejecuciones. Ver [calibración automática](#calibración-automática-de-timing).

**`technique=visible-error`** (Postgres) lee el valor completo directamente del cuerpo de un error de cast, en un solo request por expresión, en vez de inferirlo carácter por carácter.

## Auto-detección (`--technique auto`)

Sondea el punto de inyección **antes** de extraer nada, probando en orden boolean → time → error, y cada candidato se confirma dos veces (igual que `probe`/`confirm` en el resto del proyecto) antes de aceptarlo:

1. **Boolean**: compara `1=1` vs `1=2` con el payload booleano real. Si difieren en código de estado, longitud o un texto distintivo, usa ese detector.
2. **Time**: si boolean no fue concluyente, prueba `1=1`/`1=2` con sleep corto en mysql y luego en postgres, comparando latencia.
3. **Error**: si nada de lo anterior funcionó, provoca un error de sintaxis deliberado y lo compara contra firmas conocidas de Oracle/Postgres/MySQL/MSSQL/SQLite — identificando el dialecto aunque no siempre pueda auto-configurar un ataque completo (ver abajo).

El resultado siempre se imprime (`[fingerprint] technique=... detector=... dialect=... confidence=...`), nunca solo con `--verbose`, porque es una decisión que el operador necesita poder auditar. Con `confidence=confirmed` o `probable` continúa con esa configuración; con `confidence=none` falla con mensaje claro en vez de adivinar.

**Honestidad sobre el alcance**: solo auto-configura un ataque completo para error-based cuando el dialecto es Oracle (la única `conditional-error` implementada). Si detecta una firma de error de Postgres, informa el dialecto pero sugiere `--technique visible-error` manual (el `--error-value-regex` depende del mensaje exacto del objetivo, no se puede adivinar con confianza); para mysql/mssql/sqlite solo reporta el dialecto como dato.

## Estrategias de extracción

- `binary`: búsqueda binaria sobre el conjunto de caracteres. Confirma por igualdad el candidato final para rechazar valores que caigan entre dos caracteres de un charset no contiguo.
- `brute`: fuerza bruta secuencial.

El extractor confirma el final de la expresión mediante una condición de longitud antes de marcar una extracción como completa; si se alcanza `--max-length` sin confirmar el final, el resultado queda `incomplete`. Los reintentos HTTP están desactivados por defecto porque repetir una solicitud puede alterar mediciones o duplicar operaciones.

## Calibración automática de timing

Con `--technique time --auto-calibrate`, antes del ataque la herramienta envía `--calibration-samples` peticiones usando la rama falsa del payload real (sin disparar el `SLEEP`) para medir la latencia real del endpoint. El promedio medido se usa como `timing_baseline`, y el desvío estándar medido —multiplicado por `--calibration-tolerance-factor`— como `timing_tolerance`, en vez de que el operador los adivine a mano. `--timing-baseline`/`--timing-tolerance` siguen funcionando como override manual cuando no se usa `--auto-calibrate`.

## Extracción paralela y rate limiting

`--threads N` extrae expresiones distintas en paralelo (por ejemplo `--expression username --expression password_hash`), cada una sobre su propia instancia de extractor — nunca se comparte estado mutable entre workers. El paralelismo es **entre expresiones**, no entre caracteres de una misma expresión. No está soportado con `--technique time` (la concurrencia distorsionaría la medición de latencia en la que se basa esa técnica).

`--rate-limit N` limita a `N` requests por segundo compartidos entre todos los workers; útil para no saturar el objetivo o evitar controles de tasa cuando se combina con `--threads`.

## Evasión de WAF: tamper y headers

Igual que los tamper scripts de `sqlmap`, pero de selección **manual** por ahora — nunca se detecta un bloqueo y se reintenta solo (eso queda en el roadmap). `--tamper` acepta una lista separada por coma de transformaciones sobre el payload final:

- `space2comment` / `space2plus`: reemplaza espacios por `/**/` o `+`.
- `randomcase`: randomiza mayúsculas/minúsculas de keywords SQL (`AND`, `SELECT`, `SLEEP`, etc.).
- `charencode` / `doubleencode`: percent-encoding simple o doble.
- `versionedcomment`: envuelve el payload en un comentario versionado de MySQL (`/*!50000 ... */`).
- `equaltolike`: reemplaza `=` por ` LIKE ` (seguro para las comparaciones ASCII enteras que construye el proyecto).

`--tamper-profile NAME` aplica una combinación con nombre (`generic-waf`, `cloudflare`, `modsecurity`) — **heurísticas documentadas públicamente, no una garantía contra un producto comercial específico**: los WAFs cambian de reglas todo el tiempo. Combinalo con `--verbose` para confirmar que la extracción sigue funcionando después de activar un tamper.

`--random-agent` rota el User-Agent (pool de navegadores reales) y `--random-xff` randomiza `X-Forwarded-For`/`X-Originating-IP`/`X-Real-IP`/`X-Client-IP` en cada request — técnicas simples contra reglas de rate-limit/bloqueo basadas en esos headers.

## Checkpoint y resume

Cada ejecución guarda progreso incremental (posición por posición, por expresión) en un JSON bajo `--checkpoint-dir` (default `~/.blind-finder/checkpoints`), identificado por un hash de toda la configuración — cualquier cambio en el comando produce un checkpoint distinto, así que nunca se reutiliza progreso de un ataque distinto por error. El archivo se crea con permisos `0600` porque puede contener caracteres ya extraídos de un secreto parcial.

Si una ejecución se interrumpe (`Ctrl+C` o un error), el progreso queda guardado y la consola indica el identificador de checkpoint. Repetir exactamente el mismo comando agregando `--resume` continúa desde la última posición confirmada por expresión. Al completarse una extracción con éxito, su checkpoint se borra automáticamente.

## Reporte exportable

`--report-file PATH` escribe, al terminar una corrida con éxito, un resumen con el target, parámetro, técnica/detector/dialecto usados, duración de la extracción y — por cada expresión — el valor extraído, si quedó completa, su longitud y la cantidad de requests que costó. Útil para guardar y comparar resultados entre corridas (por ejemplo, uno por lab de PortSwigger) sin copiar texto de la terminal.

```bash
python3 -m cli \
  --url "https://example.test/filter" \
  --parameter tracking --query "tracking=base" \
  --expression "secret()" --true-text "TRUE" \
  --report-file "./reports/lab1.json"
```

`--report-format` elige `json` (default, legible y fácil de diffear) o `csv` (una fila por expresión). Si la corrida se interrumpe o falla, no se escribe reporte — el checkpoint sigue siendo la fuente de verdad del progreso parcial.

Con `--verbose`, cada posición resuelta ahora también muestra tiempo transcurrido y una estimación de cuánto falta (`... (12.3s elapsed, ~45.6s remaining)`), útil en labs reales donde la latencia no es despreciable.

## Estructura del proyecto

```text
Blind-Injector/
├── cli/          # interfaz de línea de comandos y raíz de composición de args
├── config/       # construcción del grafo de dependencias (factory)
├── core/         # motor, extractor, técnicas, calibración, rate limiter, checkpoint
├── detection/     # detectores de respuesta (puros, sin I/O)
├── payloads/     # construcción de condiciones/payloads e inyección de requests
├── transport/    # cliente HTTP y abstracción del transporte
├── models/       # modelos de configuración y datos (inmutables)
├── exceptions/   # excepciones del proyecto
├── utils/        # logging y utilidades varias
├── tests/        # pruebas unitarias (sin acceso a red)
├── Docs/         # documentación extendida (no versionada, ver nota abajo)
├── README.md
├── pyproject.toml
└── requirements.txt
```

## Documentación técnica

> **Nota:** la carpeta `Docs/` está excluida de git (`.gitignore`), así que estos enlaces apuntan a archivos locales que podés no tener si clonaste el repo desde cero. La bitácora de cambios de cada sesión de trabajo vive en `Docs-Claude/` (también fuera de git).

- `Docs/architecture.md`: arquitectura y flujo del sistema
- `Docs/guia-operacional.md` / `Docs/operational-guide.md`: guía operativa (ES/EN)
- `Docs/Referencia_tecnica.md`: referencia técnica del proyecto
- `Docs/Posibles_inconsistencias.md`: limitaciones y observaciones de diseño, con su estado
- `Docs/techniques.md`: contrato conceptual de técnicas y evidencia

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Todos los tests corren sin acceso a red real (fakes/mocks en el límite de `requests`).

## Seguridad y límites

- Usá la herramienta solo en entornos autorizados; nunca contra sistemas ajenos.
- El modo `--verbose` ayuda a debuggear; el archivo de log es la fuente más detallada. Ni los logs ni los checkpoints guardan payloads completos, cookies o valores extraídos más allá de lo necesario para reanudar.
- Los códigos de estado o textos de error usados como señal deben ser específicos y estables para evitar falsos positivos.
- El proyecto evita intencionadamente bypasses de WAF, evasión de controles, y payloads fuera del alcance controlado definido por la orquestación actual.

## Licencia

Consulta el archivo de metadatos del paquete y la configuración del repositorio para verificar la licencia aplicable.
