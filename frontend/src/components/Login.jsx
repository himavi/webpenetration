import { useState } from 'react'

import { login } from '../api.js'
import { AlertIcon, SpinnerIcon } from './Icons.jsx'

export default function Login({ onSuccess, onViewSample }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  const handleSubmit = async (event) => {
    event.preventDefault()
    if (busy || !username || !password) return
    setError(null)
    setBusy(true)
    try {
      await login(username, password)
      onSuccess?.()
    } catch (err) {
      setError(err.message ?? 'Login failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="auth" aria-labelledby="login-title">
      <div className="panel auth__card">
        <header className="auth__header">
          <span className="auth__badge" aria-hidden="true">
            <LockIcon />
          </span>
          <h1 id="login-title" className="auth__title">
            AI Penetration Tester
          </h1>
          <p className="auth__tagline">Sign in to access the security scanner.</p>
        </header>

        <form className="form" onSubmit={handleSubmit}>
          <label className="field">
            <span className="field__label">Username</span>
            <input
              className="input"
              type="text"
              name="username"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              autoComplete="username"
              autoFocus
            />
          </label>

          <label className="field">
            <span className="field__label">Password</span>
            <input
              className="input"
              type="password"
              name="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete="current-password"
            />
          </label>

          {error ? (
            <p className="callout callout--error" role="alert">
              <AlertIcon size={16} className="callout__icon" />
              <span>{error}</span>
            </p>
          ) : null}

          <button
            type="submit"
            className="button button--primary button--block"
            disabled={busy || !username || !password}
          >
            {busy ? <SpinnerIcon size={16} /> : null}
            {busy ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
        {onViewSample ? (
          <div className="login__sample">
            <p className="login__sample-text">No account? Browse a finished example report.</p>
            <button type="button" className="button button--secondary button--block" onClick={onViewSample}>
              View sample report
            </button>
          </div>
        ) : null}
      </div>
    </section>
  )
}

function LockIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false">
      <rect x="4.5" y="10.5" width="15" height="10" rx="2" />
      <path d="M8 10.5V7.5a4 4 0 0 1 8 0v3" />
    </svg>
  )
}
