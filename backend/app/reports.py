"""Report generation: severity summary, OWASP/CWE mapping, and HTML/PDF/JSON.

The report data is built from a scan and its findings, then rendered to:
- JSON (the full normalized scan + findings)
- interactive HTML (Jinja2 template)
- PDF (WeasyPrint, rendered from the HTML; imported lazily so the rest of the
  app works without the native PDF libraries installed)
"""

from datetime import datetime, timezone
from typing import Optional

from jinja2 import Environment, select_autoescape

from app.models import Finding, Scan, Severity
from app.schemas import FindingRead, ScanRead

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_SEVERITY_RANK = {s: i for i, s in enumerate(reversed(_SEVERITY_ORDER))}


def build_report_data(scan: Scan, findings: list[Finding]) -> dict:
    """Assemble the structured report payload from a scan and its findings."""
    scan_read = ScanRead.model_validate(scan).model_dump(mode="json")
    finding_reads = [FindingRead.model_validate(f).model_dump(mode="json") for f in findings]

    # Severity summary counts.
    summary = {s: 0 for s in _SEVERITY_ORDER}
    for f in finding_reads:
        sev = f.get("severity")
        if sev in summary:
            summary[sev] += 1

    # OWASP and CWE groupings.
    owasp_groups: dict[str, int] = {}
    cwe_groups: dict[str, int] = {}
    for f in finding_reads:
        if f.get("owasp_category"):
            owasp_groups[f["owasp_category"]] = owasp_groups.get(f["owasp_category"], 0) + 1
        if f.get("cwe_id"):
            cwe_groups[f["cwe_id"]] = cwe_groups.get(f["cwe_id"], 0) + 1

    # Sort findings most-severe first.
    finding_reads.sort(
        key=lambda f: (_SEVERITY_RANK.get(f.get("severity"), 0), f.get("id") or 0),
        reverse=True,
    )

    engines = sorted({f.get("engine") for f in finding_reads if f.get("engine")})

    return {
        "scan": scan_read,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(finding_reads),
        "severity_summary": summary,
        "owasp_summary": dict(sorted(owasp_groups.items())),
        "cwe_summary": dict(sorted(cwe_groups.items())),
        "engines": engines,
        "executive_summary": _executive_summary(scan_read, summary, len(finding_reads), engines),
        "findings": finding_reads,
    }


def _executive_summary(scan: dict, summary: dict, total: int, engines: list[str]) -> str:
    high_risk = summary.get("critical", 0) + summary.get("high", 0)
    target = scan.get("target", "the target")
    engine_text = ", ".join(engines) if engines else "no engines"
    if total == 0:
        return (
            f"The scan of {target} completed with no findings reported by {engine_text}. "
            "This does not guarantee the target is free of vulnerabilities; consider a "
            "deeper, authenticated, or longer scan."
        )
    risk_word = "no" if high_risk == 0 else str(high_risk)
    return (
        f"The scan of {target} produced {total} finding(s) across {engine_text}, "
        f"including {risk_word} high or critical issue(s). "
        f"Critical: {summary.get('critical', 0)}, High: {summary.get('high', 0)}, "
        f"Medium: {summary.get('medium', 0)}, Low: {summary.get('low', 0)}, "
        f"Info: {summary.get('info', 0)}. Prioritize remediation of the highest-severity "
        "items first."
    )


_HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Security Report — {{ scan.target }}</title>
<style>
  body { font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; color: #1a2030; margin: 2rem; }
  h1 { font-size: 1.6rem; margin-bottom: 0.25rem; }
  .muted { color: #6b7280; }
  .summary { display: flex; gap: 0.6rem; flex-wrap: wrap; margin: 1rem 0; }
  .pill { padding: 0.35rem 0.7rem; border-radius: 999px; font-weight: 600; font-size: 0.85rem; }
  .critical { background: #ff3b3b; color: #fff; }
  .high { background: #ff5c5c; color: #fff; }
  .medium { background: #f4c430; color: #1a2030; }
  .low { background: #5b8cff; color: #fff; }
  .info { background: #5bc0de; color: #1a2030; }
  .exec { background: #f4f6fb; border: 1px solid #e2e8f0; border-radius: 10px; padding: 1rem; margin: 1rem 0; }
  table { width: 100%; border-collapse: collapse; margin-top: 0.5rem; }
  th, td { text-align: left; padding: 0.35rem 0.5rem; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
  .finding { border: 1px solid #e2e8f0; border-radius: 10px; padding: 1rem; margin: 0.8rem 0; }
  .finding h3 { margin: 0 0 0.4rem; font-size: 1.05rem; }
  .badge { font-size: 0.7rem; text-transform: uppercase; font-weight: 700; padding: 0.1rem 0.45rem; border-radius: 999px; }
  .label { color: #6b7280; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.04em; }
  .mono { font-family: ui-monospace, monospace; font-size: 0.85rem; word-break: break-all; }
</style>
</head>
<body>
  <h1>AI Penetration Tester — Security Report</h1>
  <p class="muted">Target: <strong>{{ scan.target }}</strong> · Scan #{{ scan.id }} · Type: {{ scan.scan_type }} · Generated: {{ generated_at }}</p>

  <div class="summary">
    <span class="pill critical">Critical: {{ severity_summary.critical }}</span>
    <span class="pill high">High: {{ severity_summary.high }}</span>
    <span class="pill medium">Medium: {{ severity_summary.medium }}</span>
    <span class="pill low">Low: {{ severity_summary.low }}</span>
    <span class="pill info">Info: {{ severity_summary.info }}</span>
  </div>

  <div class="exec">
    <div class="label">Executive summary</div>
    <p>{{ executive_summary }}</p>
    <p class="muted">Engines: {{ engines | join(", ") }} · Total findings: {{ total_findings }}</p>
  </div>

  {% if owasp_summary %}
  <h2>OWASP Top 10 mapping</h2>
  <table>
    <tr><th>Category</th><th>Count</th></tr>
    {% for cat, count in owasp_summary.items() %}<tr><td>{{ cat }}</td><td>{{ count }}</td></tr>{% endfor %}
  </table>
  {% endif %}

  {% if cwe_summary %}
  <h2>CWE mapping</h2>
  <table>
    <tr><th>CWE</th><th>Count</th></tr>
    {% for cwe, count in cwe_summary.items() %}<tr><td>{{ cwe }}</td><td>{{ count }}</td></tr>{% endfor %}
  </table>
  {% endif %}

  <h2>Findings ({{ total_findings }})</h2>
  {% for f in findings %}
  <div class="finding">
    <h3><span class="badge {{ f.severity }}">{{ f.severity }}</span> {{ f.title }}</h3>
    <p class="muted">{{ f.engine }} · {{ f.vuln_type }}{% if f.cwe_id %} · {{ f.cwe_id }}{% endif %}{% if f.owasp_category %} · {{ f.owasp_category }}{% endif %}</p>
    {% if f.location %}<p><span class="label">Location</span><br><span class="mono">{{ f.location }}</span></p>{% endif %}
    {% if f.evidence %}<p><span class="label">Evidence</span><br><span class="mono">{{ f.evidence }}</span></p>{% endif %}
    {% if f.explanation %}<p><span class="label">Explanation</span><br>{{ f.explanation }}</p>{% endif %}
    {% if f.impact %}<p><span class="label">Impact</span><br>{{ f.impact }}</p>{% endif %}
    {% if f.ai_remediation or f.remediation %}<p><span class="label">Remediation</span><br>{{ f.ai_remediation or f.remediation }}</p>{% endif %}
  </div>
  {% else %}
  <p class="muted">No findings were reported for this scan.</p>
  {% endfor %}
</body>
</html>
"""

_jinja_env = Environment(autoescape=select_autoescape(["html", "xml"]))
_compiled_template = _jinja_env.from_string(_HTML_TEMPLATE)


def render_html(report_data: dict) -> str:
    return _compiled_template.render(**report_data)


def render_pdf(html: str) -> bytes:
    """Render HTML to PDF via WeasyPrint (imported lazily)."""
    from weasyprint import HTML  # local import: native libs only needed for PDF

    return HTML(string=html).write_pdf()


def pdf_available() -> bool:
    try:
        import weasyprint  # noqa: F401

        return True
    except Exception:  # noqa: BLE001
        return False
