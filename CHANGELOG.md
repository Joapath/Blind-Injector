# Changelog — Blind-Finder

Registro de versiones del framework. Cada entrada documenta los cambios funcionales, bugs corregidos, limitaciones conocidas y estado de verificación contra los labs Docker.

---

## v3.0 — 2026-11-01

### Resumen

Estabilización completa del motor de extracción y el flujo de enumeración (`--dump`). Se corrigen 6 bugs críticos que causaban truncamiento de datos, filas vacías y errores SQL silenciosos. Se amplía el charset por defecto y se mejora la resiliencia del oracle ante flapping bajo carga.

### Arquitectura

```
cli/          → Composición, parsing de args, flujo dump/enum      (4 módulos)
config/       → Factory de engine, calibración, fingerprint         (1 módulo)
core/         → Engine, extractor, búsqueda, técnicas, checkpoint  (11 módulos)
payloads/     → Builders de condición, inyección, tamper, error     (8 módulos)
detection/    → Detectores: text, length, status, error, timing     (7 módulos)
transport/    → HTTP client, rate limiter, header mutating          (4 módulos)
models/       → Dataclasses: request, response, attack, evidence    (6 módulos)
ui/           → Consola Rich, progress bars                         (1 módulo)
utils/        → Logging setup                                       (1 módulo)
tests/        → 364 unit tests                                     (29 archivos)
```

**Estadísticas**: 5,793 líneas de código fuente | 4,796 líneas de tests | 72 flags CLI | 3 dialectos SQL (Oracle, MySQL, PostgreSQL)

### Bugs corregidos

#### BUG-1: Separador `§` incompatible con MySQL
- **Archivo**: `cli/enum_catalog.py`
- **Síntoma**: `--dump` en MySQL extraía solo la primera columna de cada fila (ej: `31` en vez de `31§System Administrator§admin@lab.example§...`).
- **Causa raíz**: `§` (U+00A7) es multi-byte en UTF-8 (`0xC2 0xA7`). MySQL's `ASCII()` retorna el valor del primer byte (194), no el code point Unicode (167). La búsqueda binaria convergía a 167, pero la confirmación `ASCII(SUBSTRING(...)) = 167` siempre fallaba porque el valor real era 194.
- **Fix**: `ROW_SEPARATOR` cambiado de `§` a `~` (ASCII 126, single-byte). Actualizado en `DUMP_EXTRA_CHARS`, `build_row_expression()`, docstrings y tests.

#### BUG-2: Dump truncado por oracle flapping
- **Archivo**: `core/extractor.py` → `_binary_search_length()`
- **Síntoma**: Passwords extraídos incompletos (`s3cur3p@ssw` en vez de `s3cur3p@ssw0rd`).
- **Causa raíz**: Una sola respuesta incorrecta del servidor durante la búsqueda binaria de `LENGTH()` corrompe el resultado. Con `LENGTH = 28`, un flap en `mid=25` hacía converger a 25.
- **Fix**: Después de que la búsqueda binaria converge en `low`, se ejecutan 2 queries de verificación:
  1. `LENGTH(expr) >= low` debe ser True
  2. `LENGTH(expr) >= low+1` debe ser False
  - Si alguna falla → retorna `None` → fallback a extracción secuencial (sin pre-calcular longitud).
- **Costo**: +2 requests por extracción (~log2(max_length) + 3 total para el paso de longitud).

#### BUG-3: Dump vacío cuando binary search retorna 0
- **Archivo**: `core/extractor.py` → `_binary_search_length()`
- **Síntoma**: Filas del dump completamente vacías (0 caracteres extraídos).
- **Causa raíz**: Bajo carga del servidor, todas las condiciones del binary search retornaban False → `low = 0` → `extract()` trataba 0 como longitud válida (string vacío).
- **Fix**: `_binary_search_length()` nunca retorna 0. Si `low == 0`, verifica `LENGTH >= 1`: si True, el oracle estaba flaky; si False, podría ser vacío real. En ambos casos retorna `None` para forzar extracción secuencial que detecta el fin por su cuenta.

#### BUG-4: Columna truncada causa SQL error en dump
- **Archivo**: `cli/main.py` → flujo `--dump` step 1/3
- **Síntoma**: En PostgreSQL, el dump de filas retornaba todas vacías.
- **Causa raíz**: Si la extracción de columnas es incompleta (oracle flap), la última columna queda cortada (ej: `"displa"` en vez de `"display_name"`). El `build_row_expression()` genera `SELECT COALESCE("displa"::text, ...)` → PostgreSQL lanza `column "displa" does not exist` → todas las queries fallan.
- **Fix**: Cuando `result.complete == False` y hay más de una columna, se descarta la última (probablemente truncada) con warning: `[!] column extraction was incomplete; dropped last partial column 'displa'`.

#### BUG-5: `%` y `+` ausentes en DEFAULT_CHARSET
- **Archivo**: `cli/main.py`
- **Síntoma**: `--current-user` en MySQL retorna `labapp@` en vez de `labapp@%`.
- **Causa raíz**: `DEFAULT_CHARSET` (75 chars) no incluía `%` ni `+`, que son comunes en salidas SQL (hostmask MySQL, version strings, configuraciones).
- **Fix**: Charset ampliado a 77 caracteres: `a-zA-Z0-9` + ` _.,-@!()/:;#%+`.

#### BUG-6: `--auto-calibrate` no calculaba `timing_threshold`
- **Archivo**: `cli/main.py`
- **Síntoma**: `--technique time --auto-calibrate` sin `--timing-threshold` lanzaba error `"time-based techniques require sleep_seconds and timing_threshold"`.
- **Causa raíz**: `calibrate_timing()` solo calculaba `baseline` y `tolerance`, no el `threshold`. El usuario tenía que adivinar el valor correcto manualmente.
- **Fix**: Si `timing_threshold` es `None` después de calibrar, se auto-calcula como `sleep_seconds * 0.7` (misma fórmula que usa el fingerprint). Se muestra al usuario: `[calibration] auto-calibrated timing threshold: 3.50s (baseline=0.102s, sleep=5s)`.

### Mejoras de resiliencia

#### Engine probe/confirm con reintentos
- **Archivo**: `core/engine.py`
- **Antes**: Un solo intento de `probe()` + `confirm()` antes de cada extracción. Si el servidor estaba saturado entre pasos del dump, crash inmediato.
- **Después**: Loop de 3 intentos con backoff exponencial (0.5s → 1.0s → 2.0s). Solo falla si los 3 intentos fallan.

#### Health check con menos ruido
- **Archivo**: `core/extractor.py`
- **Antes**: Cada intento individual de health check generaba un `WARNING` visible en consola (24+ líneas `[!]` por dump).
- **Después**: Intentos individuales usan `INFO` (solo visible con `--verbose`). `WARNING` solo si fallan todos los intentos.

#### First retry sin health check
- **Archivo**: `core/extractor.py`
- **Antes**: Cada reintento de posición ejecutaba health check (2 requests extra).
- **Después**: El primer reintento va directo al character search. Solo a partir del segundo reintento se hace health check. Ahorra ~2 requests por flap recuperable.

#### Auto-detección respeta detector del usuario
- **Archivo**: `cli/main.py`
- **Antes**: `--technique auto` siempre sobreescribía el detector, incluso si el usuario había pasado `--true-text`.
- **Después**: Si el usuario proporcionó `--true-text`, `--expected-length` o `--expected-status`, se respeta su detector y solo se reemplaza la técnica.

### Verificación contra Docker labs

Labs: PostgreSQL en `localhost:5000`, MySQL en `localhost:5001`.
Fixture: tabla `users` con 15 filas, `administrator / s3cur3p@ssw0rd / admin@lab.example`.

| Comando | MySQL | PostgreSQL | Resultado |
|---|---|---|---|
| `--technique auto` (GET /search) | boolean/length | boolean/length | OK |
| `--technique auto` (POST /login) | — | time/timing | OK |
| `--dump -T users --dump-limit 3` | 6 columnas, fila 1 completa | 6 columnas, fila 1 completa | OK |
| `--dbs` | 4 schemas | — | OK |
| `--tables` | 7 tablas | — | OK |
| `--current-user` | `labapp@%` | — | OK |
| `--expression "(SELECT version())"` | `8.4.13` | — | OK |
| 364 unit tests | — | — | OK |

### Limitaciones conocidas

1. **Caracteres Unicode (ñ, á, í, etc.)**: `ASCII(SUBSTRING(...))` en MySQL retorna el primer byte UTF-8 para caracteres multi-byte. Nombres como "García" se extraen como "Garc". Es la misma limitación que tiene sqlmap. Solucionarlo requiere un `ConditionBuilder` dialect-aware que use `ORD()` en MySQL.

2. **Inyección numérica**: Los endpoints con contexto numérico (ej: `/stock?id=1`, `/debug?id=1`) no están soportados. El `PayloadBuilder` asume contexto string (wrappea en `'...'`). Requiere un modo de inyección `numeric` en `PayloadBuilder`.

3. **UI del dump**: Los resultados se muestran con formato plano (`[dump] col | col | col`). Falta una tabla Rich formateada como la tabla de resultados normales.

4. **`suggest_next_step`**: No implementado. Después de `--tables` debería sugerir `--dump -T <tabla>`, después de `--dump` debería sugerir explorar más tablas, etc.

---

## v2.0 — 2026-10-29

Evolución de blind-injector a framework modular con enumeración sqlmap-style. Commit: `b043017`.

- Catálogo de enumeración: `--dbs`, `--tables`, `--list-columns`, `--dump`, `--count`, `--current-db`, `--current-user`
- Flujo dump en 3 pasos: columnas → count → filas con checkpoint
- Fingerprint automático (`--technique auto`): detecta técnica, detector y dialecto
- Soporte multi-dialecto: Oracle, MySQL, PostgreSQL
- Payloads `-- ` con espacio trailing para MySQL
- WAF evasion: `--tamper`, `--tamper-profile`, `--random-agent`, `--random-xff`
- Checkpoint y resume (`--resume`)
- Reportes exportables (`--report-file`, JSON/CSV)
- Importar requests de Burp (`-r file.txt`)

## v1.0 — 2026-10-16

Primera versión funcional. Commit: `b61be5a`.

- Extracción boolean-based con búsqueda binaria y brute force
- Detector de texto (`--true-text`)
- Único dialecto: Oracle
- CLI básica con Rich progress bars
