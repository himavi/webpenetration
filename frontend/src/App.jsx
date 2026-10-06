import { useEffect, useRef, useState } from 'react'

import {
  clearToken,
  createScan,
  fetchAuthStatus,
  fetchConfig,
  fetchHealth,
  getFindings,
  getSample,
  getToken,
  sampleReportUrl,
  setUnauthorizedHandler,
  subscribeScan,
} from './api.js'
import Login from './components/Login.jsx'
import ResultsDashboard from './components/ResultsDashboard.jsx'
import ScanForm from './components/ScanForm.jsx'
import ScanProgress from './components/ScanProgress.jsx'
import ThemeToggle from './components/ThemeToggle.jsx'
import {
  AlertIcon,
  BrandMark,
  LogOutIcon,
  ScanIcon,
  ShieldIcon,
  SpinnerIcon,
} from './components/Icons.jsx'

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
  const [sample, setSample] = useState(null)
  const [sampleError, setSampleError] = useState(null)

  async function openSample() {
    setSampleError(null)
    try {
      setSample(await getSample())
    } catch (e) {
      setSampleError(e.message)
    }
  }
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

  const signOut = auth === Auth.READY && authRequired ? handleSignOut : null

  if (auth === Auth.LOADING) {
    return (
      <Shell>
        <div className="screen-state" role="status">
          <SpinnerIcon size={20} />
          <p className="screen-state__text">Loading…</p>
        </div>
      </Shell>
    )
  }

  if (auth === Auth.LOGIN && sample) {
    return (
      <Shell>
        <SampleView sample={sample} onBack={() => setSample(null)} />
      </Shell>
    )
  }

  if (auth === Auth.LOGIN) {
    return (
      <Shell>
        <Login onSuccess={() => setAuth(Auth.READY)} onViewSample={openSample} />
        {sampleError ? (
          <p className="callout callout--error login__sample-error" role="alert">
            <AlertIcon size={16} className="callout__icon" />
            <span>{sampleError}</span>
          </p>
        ) : null}
      </Shell>
    )
  }

  const idle = !scan && findings == null && !findingsLoading

  return (
    <Shell onSignOut={signOut}>
      <header className="page-header">
        <div className="page-header__text">
          <h1 className="page-header__title">Run a security scan</h1>
          <p className="page-header__tagline">
            Coordinated open-source security scanning with plain-language AI explanations.
          </p>
        </div>
        <span className={`status status--${health}`} role="status" aria-live="polite">
          <span className="status__dot" aria-hidden="true" />
          <span className="status__label">{HEALTH_LABELS[health]}</span>
        </span>
      </header>

      <div className="workspace">
        <aside className="workspace__side">
          <section className="panel scan-panel" aria-labelledby="new-scan-title">
            <div className="panel__head">
              <h2 id="new-scan-title" className="panel__title">
                New scan
              </h2>
            </div>

            <p className={`notice${config.demo_mode ? ' notice--demo' : ''}`}>
              <ShieldIcon size={16} className="notice__icon" />
              <span>
                {config.demo_mode
                  ? 'Demo mode — scanning is restricted to the bundled Juice Shop target.'
                  : 'Authorized testing only — scan systems you own or have explicit permission to test.'}
              </span>
            </p>

            <ScanForm onSubmit={handleSubmit} busy={submitting} demoTarget={config.demo_target} />

            {error ? (
              <p className="callout callout--error" role="alert">
                <AlertIcon size={16} className="callout__icon" />
                <span>{error}</span>
              </p>
            ) : null}
          </section>
        </aside>

        <div className="workspace__main">
          <ScanProgress scan={scan} />

          <ResultsDashboard scan={scan} findings={findings} loading={findingsLoading} />

          {idle ? <IdleState /> : null}
        </div>
      </div>
    </Shell>
  )
}

function SampleView({ sample, onBack }) {
  return (
    <>
      <header className="page-header">
        <div className="page-header__text">
          <h1 className="page-header__title">Sample report</h1>
          <p className="page-header__tagline">
            A finished example scan of OWASP Juice Shop, a deliberately vulnerable practice app. Read-only; sign in to
            run your own scan.
          </p>
        </div>
        <div className="sample-actions">
          <a className="button button--secondary button--sm" href={sampleReportUrl()} target="_blank" rel="noreferrer">
            Open HTML report
          </a>
          <button type="button" className="button button--primary button--sm" onClick={onBack}>
            Sign in
          </button>
        </div>
      </header>
      <ResultsDashboard scan={sample.scan} findings={sample.findings} />
    </>
  )
}

const ENGINES = ['OWASP ZAP', 'Nuclei', 'Nikto', 'sqlmap', 'Semgrep', 'Schemathesis', 'Auth checks']

function IdleState() {
  return (
    <section className="panel empty-state" aria-labelledby="idle-title">
      <span className="empty-state__icon">
        <ScanIcon size={22} />
      </span>
      <h2 id="idle-title" className="empty-state__title">
        No scan yet
      </h2>
      <p className="empty-state__text">
        Results appear here: a severity overview, filterable findings with AI explanations and
        fixes, and downloadable HTML, PDF and JSON reports.
      </p>
      <ul className="engine-list" aria-label="scanning engines">
        {ENGINES.map((name) => (
          <li key={name} className="chip">
            {name}
          </li>
        ))}
      </ul>
    </section>
  )
}

function Shell({ children, onSignOut = null }) {
  return (
    <div className="shell">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <header className="topbar">
        <div className="topbar__inner">
          <span className="brand">
            <BrandMark size={28} />
            <span className="brand__name">AI Pen Tester</span>
          </span>
          <div className="topbar__actions">
            <ThemeToggle />
            {onSignOut ? (
              <button type="button" className="button button--secondary topbar__signout" onClick={onSignOut}>
                <LogOutIcon size={16} />
                <span className="topbar__signout-label">Sign out</span>
              </button>
            ) : null}
          </div>
        </div>
      </header>
      <main id="main" className="main" tabIndex={-1}>
        {children}
      </main>
      <footer className="footer">
        <div className="footer__inner">
          <p className="footer__credit">
            Built by{' '}
            <a className="footer__link" href="https://hksingh.vercel.app" target="_blank" rel="noreferrer">
              Himanshu Kumar Singh
            </a>
          </p>
          <a
            className="footer__link"
            href="https://github.com/himavi/webpenetration"
            target="_blank"
            rel="noreferrer"
          >
            Source on GitHub
          </a>
        </div>
      </footer>
    </div>
  )
}
