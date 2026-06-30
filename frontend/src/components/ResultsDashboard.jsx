import { useMemo, useState } from 'react'

import { reportUrl } from '../api.js'
import FindingsList from './FindingsList.jsx'
import SeveritySummary from './SeveritySummary.jsx'

const SEVERITY_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']

export default function ResultsDashboard({ scan, findings, loading = false }) {
  const [severity, setSeverity] = useState('all')
  const [engine, setEngine] = useState('all')
  const [vulnType, setVulnType] = useState('')
  const [sort, setSort] = useState('severity')

  const engines = useMemo(
    () => (findings ? [...new Set(findings.map((f) => f.engine))].sort() : []),
    [findings],
  )

  const filtered = useMemo(() => {
    if (!findings) return []
    const list = findings.filter(
      (f) =>
        (severity === 'all' || f.severity === severity) &&
        (engine === 'all' || f.engine === engine) &&
        (!vulnType || (f.vuln_type || '').toLowerCase().includes(vulnType.toLowerCase())),
    )
    return [...list].sort((a, b) =>
      sort === 'engine'
        ? (a.engine || '').localeCompare(b.engine || '')
        : (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0),
    )
  }, [findings, severity, engine, vulnType, sort])

  if (loading) {
    return <p className="findings__empty">loading findings…</p>
  }
  if (findings == null) {
    return null
  }

  return (
    <section className="dashboard" aria-label="results dashboard">
      <SeveritySummary findings={findings} />

      {findings.length === 0 ? (
        <p className="findings__empty">No findings were reported for this scan.</p>
      ) : (
        <>
          {scan?.id != null && (
            <div className="downloads">
              <span className="downloads__label">Download report:</span>
              <a className="button button--ghost" href={reportUrl(scan.id, 'html')} target="_blank" rel="noreferrer">
                HTML
              </a>
              <a className="button button--ghost" href={reportUrl(scan.id, 'pdf')} target="_blank" rel="noreferrer">
                PDF
              </a>
              <a className="button button--ghost" href={reportUrl(scan.id, 'json')} target="_blank" rel="noreferrer">
                JSON
              </a>
            </div>
          )}

          <div className="filters">
            <label>
              <span>Severity</span>
              <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
                <option value="all">all</option>
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </label>
            <label>
              <span>Engine</span>
              <select value={engine} onChange={(e) => setEngine(e.target.value)}>
                <option value="all">all</option>
                {engines.map((e2) => (
                  <option key={e2} value={e2}>
                    {e2}
                  </option>
                ))}
              </select>
            </label>
            <label>
              <span>Type</span>
              <input
                type="text"
                placeholder="filter by type"
                value={vulnType}
                onChange={(e) => setVulnType(e.target.value)}
              />
            </label>
            <label>
              <span>Sort</span>
              <select value={sort} onChange={(e) => setSort(e.target.value)}>
                <option value="severity">severity</option>
                <option value="engine">engine</option>
              </select>
            </label>
          </div>

          <FindingsList findings={filtered} total={findings.length} />
        </>
      )}
    </section>
  )
}
