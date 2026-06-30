const ORDER = ['critical', 'high', 'medium', 'low', 'info']

export default function SeveritySummary({ findings }) {
  const counts = ORDER.reduce((acc, sev) => ({ ...acc, [sev]: 0 }), {})
  for (const finding of findings || []) {
    if (finding.severity in counts) counts[finding.severity] += 1
  }

  return (
    <div className="summary" aria-label="finding severity counts">
      {ORDER.map((sev) => (
        <span key={sev} className={`summary__pill badge--${sev}`}>
          {sev}: {counts[sev]}
        </span>
      ))}
    </div>
  )
}
