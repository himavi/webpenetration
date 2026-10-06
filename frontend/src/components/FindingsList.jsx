import { SearchIcon, WrenchIcon } from './Icons.jsx'

export default function FindingsList({ findings, total = null }) {
  if (findings == null) {
    return null
  }
  if (findings.length === 0) {
    return (
      <div className="panel empty-state empty-state--compact" role="status">
        <span className="empty-state__icon">
          <SearchIcon size={20} />
        </span>
        <p className="empty-state__text">No findings match the current filters.</p>
      </div>
    )
  }

  const showOf = total != null && total !== findings.length
  const heading = showOf ? `Findings (${findings.length} of ${total})` : `Findings (${findings.length})`

  return (
    <section className="findings" aria-label="findings">
      <h2 className="findings__title" aria-live="polite">
        {heading}
      </h2>
      <ul className="findings__list">
        {findings.map((finding) => (
          <FindingCard key={finding.id} finding={finding} />
        ))}
      </ul>
    </section>
  )
}

function FindingCard({ finding }) {
  const fix = finding.ai_remediation || finding.remediation
  const titleId = `finding-${finding.id}-title`

  return (
    <li className={`finding finding--${finding.severity}`}>
      <article aria-labelledby={titleId}>
        <header className="finding__head">
          <div className="finding__badges">
            <span className={`badge badge--${finding.severity}`}>
              <span className={`sev-dot sev-dot--${finding.severity}`} aria-hidden="true" />
              {finding.severity}
            </span>
            <span className="finding__engine">{finding.engine}</span>
          </div>
          <h3 id={titleId} className="finding__name">
            {finding.title}
          </h3>
          {finding.location ? (
            <p className="finding__location">
              <span className="sr-only">location: </span>
              <code>{finding.location}</code>
              {finding.affected_param ? (
                <span className="finding__param">
                  param <code>{finding.affected_param}</code>
                </span>
              ) : null}
            </p>
          ) : null}
        </header>

        {finding.explanation || finding.impact || fix || finding.evidence ? (
          <div className="finding__body">
            {finding.explanation ? (
              <div className="finding__section">
                <h4 className="finding__label">What it means</h4>
                <p className="finding__text">{finding.explanation}</p>
              </div>
            ) : null}
            {finding.impact ? (
              <div className="finding__section">
                <h4 className="finding__label">Impact</h4>
                <p className="finding__text">{finding.impact}</p>
              </div>
            ) : null}
            {finding.evidence ? (
              <div className="finding__section">
                <h4 className="finding__label">Evidence</h4>
                <pre className="finding__evidence">
                  <code>{finding.evidence}</code>
                </pre>
              </div>
            ) : null}
            {fix ? (
              <div className="finding__fix">
                <h4 className="finding__label finding__label--fix">
                  <WrenchIcon size={14} />
                  How to fix
                </h4>
                <p className="finding__text">{fix}</p>
              </div>
            ) : null}
          </div>
        ) : null}

        <dl className="finding__facts">
          <div className="fact">
            <dt>Type</dt>
            <dd>{finding.vuln_type}</dd>
          </div>
          {finding.cwe_id ? (
            <div className="fact">
              <dt>CWE</dt>
              <dd>{finding.cwe_id}</dd>
            </div>
          ) : null}
          {finding.owasp_category ? (
            <div className="fact">
              <dt>OWASP</dt>
              <dd>{finding.owasp_category}</dd>
            </div>
          ) : null}
        </dl>
      </article>
    </li>
  )
}
