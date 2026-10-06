const ORDER = ['critical', 'high', 'medium', 'low', 'info']

export default function SeveritySummary({ findings }) {
  const counts = ORDER.reduce((acc, sev) => ({ ...acc, [sev]: 0 }), {})
  for (const finding of findings || []) {
    if (finding.severity in counts) counts[finding.severity] += 1
  }
  const total = ORDER.reduce((sum, sev) => sum + counts[sev], 0)

  return (
    <div className="summary">
      <div className="summary__bar" aria-hidden="true">
        {total === 0 ? (
          <span className="summary__segment summary__segment--empty" />
        ) : (
          ORDER.filter((sev) => counts[sev] > 0).map((sev) => (
            <span
              key={sev}
              className={`summary__segment summary__segment--${sev}`}
              style={{ flexGrow: counts[sev] }}
            />
          ))
        )}
      </div>
      <ul className="summary__tiles" aria-label="finding severity counts">
        {ORDER.map((sev) => (
          <li key={sev} className={`summary__tile${counts[sev] === 0 ? ' is-zero' : ''}`}>
            <span className="sr-only">
              {sev}: {counts[sev]}
            </span>
            <span className="summary__label" aria-hidden="true">
              <span className={`sev-dot sev-dot--${sev}`} />
              {sev}
            </span>
            <span className="summary__count" aria-hidden="true">
              {counts[sev]}
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}
