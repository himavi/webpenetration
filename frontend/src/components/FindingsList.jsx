const SEVERITY_ORDER = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }

function bySeverity(a, b) {
  return (SEVERITY_ORDER[b.severity] ?? 0) - (SEVERITY_ORDER[a.severity] ?? 0)
}

export default function FindingsList({ findings, loading = false }) {
  if (loading) {
    return <p className="findings__empty">loading findings…</p>
  }
  if (findings == null) {
    return null
  }
  if (findings.length === 0) {
    return <p className="findings__empty">No findings reported for this scan.</p>
  }

  const sorted = [...findings].sort(bySeverity)

  return (
    <section className="findings" aria-label="findings">
      <h2 className="findings__title">Findings ({findings.length})</h2>
      <ul className="findings__list">
        {sorted.map((finding) => (
          <li key={finding.id} className={`finding finding--${finding.severity}`}>
            <div className="finding__head">
              <span className={`badge badge--${finding.severity}`}>{finding.severity}</span>
              <span className="finding__name">{finding.title}</span>
              <span className="finding__engine">{finding.engine}</span>
            </div>
            <dl className="finding__meta">
              <div>
                <dt>type</dt>
                <dd>{finding.vuln_type}</dd>
              </div>
              {finding.location ? (
                <div>
                  <dt>location</dt>
                  <dd>{finding.location}</dd>
                </div>
              ) : null}
              {finding.cwe_id ? (
                <div>
                  <dt>cwe</dt>
                  <dd>{finding.cwe_id}</dd>
                </div>
              ) : null}
              {finding.evidence ? (
                <div>
                  <dt>evidence</dt>
                  <dd>{finding.evidence}</dd>
                </div>
              ) : null}
              {finding.remediation ? (
                <div>
                  <dt>fix</dt>
                  <dd>{finding.remediation}</dd>
                </div>
              ) : null}
            </dl>
          </li>
        ))}
      </ul>
    </section>
  )
}
