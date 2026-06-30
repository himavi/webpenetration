export default function FindingsList({ findings, total = null }) {
  if (findings == null) {
    return null
  }
  if (findings.length === 0) {
    return <p className="findings__empty">No findings match the current filters.</p>
  }

  const showOf = total != null && total !== findings.length
  const heading = showOf ? `Findings (${findings.length} of ${total})` : `Findings (${findings.length})`

  return (
    <section className="findings" aria-label="findings">
      <h2 className="findings__title">{heading}</h2>
      <ul className="findings__list">
        {findings.map((finding) => (
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
              {finding.owasp_category ? (
                <div>
                  <dt>owasp</dt>
                  <dd>{finding.owasp_category}</dd>
                </div>
              ) : null}
              {finding.evidence ? (
                <div>
                  <dt>evidence</dt>
                  <dd>{finding.evidence}</dd>
                </div>
              ) : null}
              {finding.explanation ? (
                <div>
                  <dt>explanation</dt>
                  <dd>{finding.explanation}</dd>
                </div>
              ) : null}
              {finding.impact ? (
                <div>
                  <dt>impact</dt>
                  <dd>{finding.impact}</dd>
                </div>
              ) : null}
              {finding.ai_remediation || finding.remediation ? (
                <div>
                  <dt>fix</dt>
                  <dd>{finding.ai_remediation || finding.remediation}</dd>
                </div>
              ) : null}
            </dl>
          </li>
        ))}
      </ul>
    </section>
  )
}
