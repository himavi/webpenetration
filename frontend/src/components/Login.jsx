import { useState } from 'react'

import { login } from '../api.js'

export default function Login({ onSuccess }) {
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
    <main className="app app--login">
      <header className="app__header">
        <div className="login__lock" aria-hidden="true">&#128274;</div>
        <h1>AI Penetration Tester</h1>
        <p className="app__tagline">Sign in to access the security scanner.</p>
      </header>

      <form className="scan-form" onSubmit={handleSubmit}>
        <label className="field">
          <span className="field__label">Username</span>
          <input
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
            type="password"
            name="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete="current-password"
          />
        </label>

        {error ? (
          <p className="app__error" role="alert">
            {error}
          </p>
        ) : null}

        <button type="submit" className="button" disabled={busy || !username || !password}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </main>
  )
}
