import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import App from './App.jsx'

const SAMPLE = {
  scan: { id: null, target: 'http://juiceshop:3000', scan_type: 'dast', status: 'done', progress: 100, message: 'done' },
  findings: [
    { id: 1, scan_id: null, engine: 'zap', vuln_type: 'sql-injection', severity: 'critical', title: 'SQL Injection in login endpoint', location: 'http://juiceshop:3000/rest/user/login' },
  ],
}

function fetchMock() {
  return vi.fn(async (url) => {
    if (url.endsWith('/api/auth/status')) return { ok: true, json: async () => ({ auth_required: true }) }
    if (url.endsWith('/api/sample')) return { ok: true, json: async () => SAMPLE }
    if (url.endsWith('/health')) return { ok: true, json: async () => ({ status: 'ok' }) }
    return { ok: false, status: 401, json: async () => ({ detail: 'authentication required' }) }
  })
}

describe('public sample report', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('opens the sample report from the sign-in screen without logging in', async () => {
    const fetch = fetchMock()
    vi.stubGlobal('fetch', fetch)
    render(<App />)

    await userEvent.click(await screen.findByRole('button', { name: /view sample report/i }))

    expect(await screen.findByRole('heading', { name: /sample report/i })).toBeInTheDocument()
    expect(screen.getByText('SQL Injection in login endpoint')).toBeInTheDocument()
    // Only the public endpoint was used: no scan API calls.
    expect(fetch.mock.calls.some(([u]) => u.includes('/api/scans'))).toBe(false)

    await userEvent.click(screen.getByRole('button', { name: /sign in/i }))
    expect(await screen.findByLabelText(/username/i)).toBeInTheDocument()
  })
})
