import { useEffect, useRef, useState } from 'react'

import {
  clearToken,
  createScan,
  fetchAuthStatus,
  fetchConfig,
  fetchHealth,
  getFindings,
  getToken,
  setUnauthorizedHandler,
  subscribeScan,
} from './api.js'
import Login from './components/Login.jsx'
import ResultsDashboard from './components/ResultsDashboard.jsx'
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

const Auth = {
  LOADING: 'loading',
  LOGIN: 'login',
  READY: 'ready',
}

export default function App() {
  const [auth, setAuth] = useState(Auth.LOADING)
  const [authRequired, setAuthRequired] = useState(false)
  const [health, setHealth] = useState(Health.LOADING)
  const [config, setConfig] = useState({ demo_mode: false, demo_target: null })
  const [scan, setScan] = useState(null)
  const [findings, setFindings] = useState(null)
  const [findingsLoading, setFindingsLoading] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)
  const unsubscribeRef = useRef(null)

  // Determine whether a login is needed, and bounce back to login on any 401.
  useEffect(() => {
    let cancelled = false
    setUnauthorizedHandler(() => setAuth(Auth.LOGIN))
    fetchAuthStatus()
      .then(({ auth_required }) => {
        if (cancelled) return
        setAuthRequired(Boolean(auth_required))
        if (!auth_required || getToken()) setAuth(Auth.READY)
        else setAuth(Auth.LOGIN)
      })
      .catch(() => {
        if (!cancelled) setAuth(Auth.READY)
      })
    return () => {
      cancelled = true
      setUnauthorizedHandler(null)
    }
  }, [])

  // Once authenticated, load health + config.
  useEffect(() => {
    if (auth !== Auth.READY) return
    let cancelled = false
    fetchHealth()
      .then((data) => {
        if (!cancelled) setHealth(data?.status === 'ok' ? Health.HEALTHY : Health.UNHEALTHY)
      })
      .catch(() => {
        if (!cancelled) setHealth(Health.UNHEALTHY)
      })
    fetchConfig()
      .then((cfg) => {
        if (!cancelled) setConfig(cfg)
      })
      .catch(() => {})
    return () => {
      cancelled = true
    }
  }, [auth])

  // Tear down any live subscription when the app unmounts.
  useEffect(() => () => unsubscribeRef.current?.(), [])

  const handleSignOut = () => {
    unsubscribeRef.current?.()
    unsubscribeRef.current = null
    clearToken()
    setScan(null)
    setFindings(null)
    setError(null)
    setHealth(Health.LOADING)
    setAuth(Auth.LOGIN)
  }

  const handleSubmit = async ({ target, scanType, authorized, file }) => {
    setError(null)
    setSubmitting(true)
    setFindings(null)
    unsubscribeRef.current?.()
    unsubscribeRef.current = null

    try {
      const created = await createScan({ target, scanType, authorized, file })
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

  if (auth === Auth.LOADING) {
    return (
      <main className="app">
        <p className="app__tagline">Loading…</p>
      </main>
    )
  }

  if (auth === Auth.LOGIN) {
    return <Login onSuccess={() => setAuth(Auth.READY)} />
  }

  return (
    <main className="app">
      <header className="app__header">
        {authRequired ? (
          <button type="button" className="app__signout" onClick={handleSignOut}>
            Sign out
          </button>
        ) : null}
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
        {config.demo_mode
          ? 'Demo mode — scanning is restricted to the bundled Juice Shop target.'
          : 'Authorized testing only — scan systems you own or have explicit permission to test.'}
      </p>

      <ScanForm onSubmit={handleSubmit} busy={submitting} demoTarget={config.demo_target} />

      {error ? (
        <p className="app__error" role="alert">
          {error}
        </p>
      ) : null}

      <ScanProgress scan={scan} />

      <ResultsDashboard scan={scan} findings={findings} loading={findingsLoading} />
    </main>
  )
}
