import { useMemo, useState } from 'react'

import { reportUrl } from '../api.js'
import FindingsList from './FindingsList.jsx'
import { CheckCircleIcon, DownloadIcon, InfoIcon, SearchIcon, SpinnerIcon } from './Icons.jsx'
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
    return (
      <section className="panel dashboard dashboard--loading" aria-busy="true">
        <p className="loading-line" role="status">
          <SpinnerIcon size={16} />
          Loading findings…
        </p>
        <div className="skeleton skeleton--bar" />
        <div className="skeleton-tiles">
          {[0, 1, 2, 3, 4].map((i) => (
            <div key={i} className="skeleton skeleton--tile" />
          ))}
        </div>
        <div className="skeleton skeleton--card" />
        <div className="skeleton skeleton--card" />
      </section>
    )
  }
  if (findings == null) {
    return null
  }

  const downloads = [
    { format: 'html', label: 'HTML' },
    { format: 'pdf', label: 'PDF' },
    { format: 'json', label: 'JSON' },
  ]

  return (
    <section className="dashboard" aria-label="results dashboard">
      <div className="panel overview">
        <div className="overview__head">
          <div>
            <h2 className="panel__title">Results</h2>
            <p className="overview__meta">
              {findings.length} {findings.length === 1 ? 'finding' : 'findings'}
              {scan?.target ? (
                <>
                  {' '}
                  · <code>{scan.target}</code>
                </>
              ) : null}
            </p>
          </div>
          {findings.length > 0 && scan?.id != null && (
            <div className="downloads" role="group" aria-labelledby="downloads-label">
              <span id="downloads-label" className="downloads__label">
                Download report
              </span>
              <div className="downloads__buttons">
                {downloads.map(({ format, label }) => (
                  <a
                    key={format}
                    className="button button--secondary button--sm"
                    href={reportUrl(scan.id, format)}
                    target="_blank"
                    rel="noreferrer"
                  >
                    <DownloadIcon size={15} />
                    {label}
                  </a>
                ))}
              </div>
            </div>
          )}
        </div>

        <SeveritySummary findings={findings} />
      </div>

      {findings.length === 0 ? (
        <div className="panel empty-state empty-state--compact">
          {scan?.status === 'failed' ? (
            <span className="empty-state__icon">
              <InfoIcon size={22} />
            </span>
          ) : (
            <span className="empty-state__icon empty-state__icon--ok">
              <CheckCircleIcon size={22} />
            </span>
          )}
          <p className="empty-state__text">No findings were reported for this scan.</p>
        </div>
      ) : (
        <>
          <div className="filters" role="search" aria-label="filter findings">
            <label className="filter">
              <span className="filter__label">Severity</span>
              <select className="input select" value={severity} onChange={(e) => setSeverity(e.target.value)}>
                <option value="all">all</option>
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </label>
            <label className="filter">
              <span className="filter__label">Engine</span>
              <select className="input select" value={engine} onChange={(e) => setEngine(e.target.value)}>
                <option value="all">all</option>
                {engines.map((e2) => (
                  <option key={e2} value={e2}>
                    {e2}
                  </option>
                ))}
              </select>
            </label>
            <label className="filter filter--grow">
              <span className="filter__label">Type</span>
              <span className="input-icon">
                <SearchIcon size={16} />
                <input
                  className="input"
                  type="text"
                  placeholder="filter by type"
                  value={vulnType}
                  onChange={(e) => setVulnType(e.target.value)}
                />
              </span>
            </label>
            <label className="filter">
              <span className="filter__label">Sort</span>
              <select className="input select" value={sort} onChange={(e) => setSort(e.target.value)}>
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
