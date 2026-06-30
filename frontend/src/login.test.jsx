import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import App from './App.jsx'

// Auth is required; login returns a token, after which the app loads.
function authFetch() {
  return vi.fn(async (url, options) => {
    if (typeof url === 'string' && url.endsWith('/api/auth/status')) {
      return { ok: true, json: async () => ({ auth_required: true }) }
    }
    if (typeof url === 'string' && url.endsWith('/api/auth/login') && options?.method === 'POST') {
      const body = JSON.parse(options.body)
      if (body.password === 'right') {
        return { ok: true, json: async () => ({ token: 'test-token' }) }
      }
      return { ok: false, status: 401, json: async () => ({ detail: 'Invalid username or password.' }) }
    }
    if (typeof url === 'string' && url.endsWith('/health')) {
      return { ok: true, json: async () => ({ status: 'ok', service: 'x', version: '0.1.0' }) }
    }
    if (typeof url === 'string' && url.endsWith('/api/config')) {
      return { ok: true, json: async () => ({ demo_mode: false, demo_target: null }) }
    }
    return { ok: false, status: 404, json: async () => ({}) }
  })
}

describe('login gate', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.stubGlobal('fetch', authFetch())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  it('shows the login form when auth is required', async () => {
    render(<App />)
    expect(await screen.findByRole('button', { name: /sign in/i })).toBeInTheDocument()
    // The scan form should not be visible yet.
    expect(screen.queryByText(/start scan/i)).not.toBeInTheDocument()
  })

  it('rejects a wrong password and shows an error', async () => {
    const user = userEvent.setup()
    render(<App />)

    await user.type(await screen.findByLabelText(/username/i), 'recruiter')
    await user.type(screen.getByLabelText(/password/i), 'wrong')
    await user.click(screen.getByRole('button', { name: /sign in/i }))

    expect(await screen.findByRole('alert')).toHaveTextContent(/invalid username or password/i)
  })

  it('logs in with the right password and reveals the app', async () => {
    const user = userEvent.setup()
    render(<App />)

    await user.type(await screen.findByLabelText(/username/i), 'recruiter')
    await user.type(screen.getByLabelText(/password/i), 'right')
    await user.click(screen.getByRole('button', { name: /sign in/i }))

    expect(await screen.findByText('backend healthy')).toBeInTheDocument()
    expect(localStorage.getItem('aip_token')).toBe('test-token')
  })
})
