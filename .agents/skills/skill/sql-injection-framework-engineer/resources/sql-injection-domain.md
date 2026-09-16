# SQL Injection Domain Knowledge

## Supported Techniques

Blind-Injector should support multiple SQL Injection techniques.

Current domain:

- Boolean-based Blind SQL Injection.
- Time-based Blind SQL Injection.
- Error-based SQL Injection.

Future:

- UNION based SQL Injection.
- Stacked queries.
- Out-of-band techniques.

---

# Blind SQL Injection Concepts

Blind SQL Injection relies on extracting information through observable differences.

Possible signals:

- Response text.
- Response length.
- HTTP status.
- Error messages.
- Response timing.

Detection logic must remain independent from extraction logic.

---

# Boolean-based Extraction

Extraction process:

1. Generate conditional SQL expression.
2. Inject payload.
3. Analyze response.
4. Determine TRUE/FALSE result.
5. Reconstruct data.

Optimization:

Prefer binary search over brute force when possible.

Example:

Instead of:

a-z
0-9

checking every character:

Use:

ASCII(value) >= midpoint

to reduce requests.

---

# Time-based Extraction

Time-based techniques rely on measurable delays.

Important considerations:

- Network latency.
- Baseline response time.
- Timing threshold.
- Noise handling.
- Retries.

Never assume a delay alone proves a condition.

---

# Database Abstraction

Avoid hardcoding database-specific behavior.

Use abstractions:

Example:

DatabaseDialect

Implementations:

- OracleDialect.
- MySQLDialect.
- PostgreSQLDialect.
- MSSQLDialect.

Each dialect handles:

- String extraction.
- ASCII conversion.
- Sleep functions.
- Metadata queries.

---

# Payload Design

Payloads should be:

- Composable.
- Testable.
- Database-aware.
- Independent from HTTP.

Avoid:

```python
requests.get(url + "' OR 1=1--")
