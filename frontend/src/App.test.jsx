import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

import App from './App.jsx'

// Fake fetch keyed by URL so the auth-status check, health, and config calls
// each resolve correctly. `healthOk` controls the /health response.
function fakeFetch({ healthOk = true } = {}) {
  return vi.fn(async (url) => {
    if (typeof url === 'string' && url.endsWith('/api/auth/status')) {
      return { ok: true, json: async () => ({ auth_required: false }) }
    }
    if (typeof url === 'string' && url.endsWith('/health')) {
      if (!healthOk) throw new Error('network down')
      return { ok: true, json: async () => ({ status: 'ok', service: 'x', version: '0.1.0' }) }
    }
    if (typeof url === 'string' && url.endsWith('/api/config')) {
      return { ok: true, json: async () => ({ demo_mode: false, demo_target: null }) }
    }
    return { ok: false, status: 404, json: async () => ({}) }
  })
}

describe('App status page', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  it('shows "backend healthy" when the health endpoint reports ok', async () => {
    vi.stubGlobal('fetch', fakeFetch({ healthOk: true }))

    render(<App />)

    expect(await screen.findByText('backend healthy')).toBeInTheDocument()
  })

  it('shows "backend unavailable" when the request fails', async () => {
    vi.stubGlobal('fetch', fakeFetch({ healthOk: false }))

    render(<App />)

    expect(await screen.findByText('backend unavailable')).toBeInTheDocument()
  })
})
