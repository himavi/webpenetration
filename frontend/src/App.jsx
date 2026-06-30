import { useEffect, useState } from 'react'

import { fetchHealth } from './api.js'

const Status = {
  LOADING: 'loading',
  HEALTHY: 'healthy',
  UNHEALTHY: 'unhealthy',
}

const LABELS = {
  [Status.LOADING]: 'checking backend…',
  [Status.HEALTHY]: 'backend healthy',
  [Status.UNHEALTHY]: 'backend unavailable',
}

export default function App() {
  const [status, setStatus] = useState(Status.LOADING)
  const [info, setInfo] = useState(null)

  useEffect(() => {
    let cancelled = false

    fetchHealth()
      .then((data) => {
        if (cancelled) return
        setInfo(data)
        setStatus(data?.status === 'ok' ? Status.HEALTHY : Status.UNHEALTHY)
      })
      .catch(() => {
        if (!cancelled) setStatus(Status.UNHEALTHY)
      })

    return () => {
      cancelled = true
    }
  }, [])

  return (
    <main className="app">
      <header className="app__header">
        <h1>AI Penetration Tester</h1>
        <p className="app__tagline">
          Coordinated open-source security scanning with plain-language AI
          explanations.
        </p>
      </header>

      <section className={`status status--${status}`} role="status" aria-live="polite">
        <span className="status__dot" aria-hidden="true" />
        <span className="status__label">{LABELS[status]}</span>
      </section>

      {info?.version ? (
        <p className="app__meta">backend version {info.version}</p>
      ) : null}
    </main>
  )
}
