import { useEffect, useRef, useState } from 'react'

import { createScan, fetchHealth, getFindings, subscribeScan } from './api.js'
import FindingsList from './components/FindingsList.jsx'
import ScanForm from './components/ScanForm.jsx'
import ScanProgress from './components/ScanProgress.jsx'

const Health = {
  LOADING: 'loading',
  HEALTHY: 'healthy',
  UNHEALTHY: 'unhealthy',
}

const HEALTH_LABELS = {
  [Health.LOADING]: 'checking backend…',
  [Health.HEALTHY]: 'backend healthy',
  [Health.UNHEALTHY]: 'backend unavailable',
}

export default function App() {
  const [health, setHealth] = useState(Health.LOADING)
  const [scan, setScan] = useState(null)
  const [findings, setFindings] = useState(null)
  const [findingsLoading, setFindingsLoading] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)
  const unsubscribeRef = useRef(null)

  useEffect(() => {
    let cancelled = false
    fetchHealth()
      .then((data) => {
        if (!cancelled) setHealth(data?.status === 'ok' ? Health.HEALTHY : Health.UNHEALTHY)
      })
      .catch(() => {
        if (!cancelled) setHealth(Health.UNHEALTHY)
      })
    return () => {
      cancelled = true
    }
  }, [])

  // Tear down any live subscription when the app unmounts.
  useEffect(() => () => unsubscribeRef.current?.(), [])

  const handleSubmit = async ({ target, scanType, authorized }) => {
    setError(null)
    setSubmitting(true)
    setFindings(null)
    unsubscribeRef.current?.()
    unsubscribeRef.current = null

    try {
      const created = await createScan({ target, scanType, authorized })
      setScan(created)
      unsubscribeRef.current = subscribeScan(created.id, {
        onUpdate: (data) => {
          setScan((prev) => ({ ...prev, ...data }))
          if (data.status === 'done' || data.status === 'failed') {
            setFindingsLoading(true)
            getFindings(created.id)
              .then((items) => setFindings(items))
              .catch(() => setFindings([]))
              .finally(() => setFindingsLoading(false))
          }
        },
      })
    } catch (err) {
      setScan(null)
      setError(err.message ?? 'Failed to start scan')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <main className="app">
      <header className="app__header">
        <h1>AI Penetration Tester</h1>
        <p className="app__tagline">
          Coordinated open-source security scanning with plain-language AI explanations.
        </p>
        <span className={`status status--${health}`} role="status" aria-live="polite">
          <span className="status__dot" aria-hidden="true" />
          <span className="status__label">{HEALTH_LABELS[health]}</span>
        </span>
      </header>

      <p className="app__notice">
        Authorized testing only — scan systems you own or have explicit permission to test.
      </p>

      <ScanForm onSubmit={handleSubmit} busy={submitting} />

      {error ? (
        <p className="app__error" role="alert">
          {error}
        </p>
      ) : null}

      <ScanProgress scan={scan} />

      <FindingsList findings={findings} loading={findingsLoading} />
    </main>
  )
}
