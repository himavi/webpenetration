"""Tests for the sqlmap adapter: injection-report parsing and availability."""

from app.adapters.sqlmap import SqlmapAdapter
from app.models import Severity

SAMPLE_OUTPUT = """\
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.9#stable}
|_ -| . [(]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[*] starting @ 12:00:00 /2026-06-30/

[12:00:01] [INFO] testing connection to the target URL
[12:00:05] [INFO] GET parameter 'id' is 'AND boolean-based blind' injectable
sqlmap identified the following injection point(s) with a total of 52 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1234=1234

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 9999 FROM (SELECT(SLEEP(5)))abc)
---
[12:00:30] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12

[*] ending @ 12:00:31 /2026-06-30/
"""

NO_INJECTION_OUTPUT = """\
[12:00:01] [INFO] testing connection to the target URL
[12:00:20] [WARNING] GET parameter 'id' does not seem to be injectable
[12:00:21] [CRITICAL] all tested parameters do not appear to be injectable.
"""


def test_parse_confirmed_injection():
    adapter = SqlmapAdapter()
    adapter._last_target = "http://vuln.test/item?id=1"

    findings = adapter.parse(SAMPLE_OUTPUT)
    assert len(findings) == 1

    finding = findings[0]
    assert finding.engine == "sqlmap"
    assert finding.vuln_type == "sql-injection"
    assert finding.severity is Severity.HIGH
    assert finding.affected_param == "id"
    assert finding.cwe_id == "CWE-89"
    assert finding.owasp_category == "A03:2021-Injection"
    assert finding.location == "http://vuln.test/item?id=1"
    assert "boolean-based blind" in finding.evidence
    assert "dbms: MySQL" in finding.evidence
    assert "payload:" in finding.evidence


def test_parse_no_injection_returns_empty():
    assert SqlmapAdapter().parse(NO_INJECTION_OUTPUT) == []
    assert SqlmapAdapter().parse("") == []


def test_parse_multiple_parameters():
    raw = (
        "sqlmap identified the following injection point(s):\n"
        "---\n"
        "Parameter: id (GET)\n"
        "    Type: boolean-based blind\n"
        "    Payload: id=1 AND 1=1\n"
        "Parameter: name (POST)\n"
        "    Type: error-based\n"
        "    Payload: name=x' AND GTID_SUBSET(...)\n"
        "---\n"
        "back-end DBMS: PostgreSQL\n"
    )
    findings = SqlmapAdapter().parse(raw)
    assert {f.affected_param for f in findings} == {"id", "name"}
    assert all(f.cwe_id == "CWE-89" for f in findings)


def test_is_available_false_when_binary_missing():
    assert SqlmapAdapter(binary="definitely-not-a-real-sqlmap-xyz").is_available() is False
