import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

import App from './App.jsx'

describe('App status page', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  it('shows "backend healthy" when the health endpoint reports ok', async () => {
    fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        status: 'ok',
        service: 'ai-pentester-backend',
        version: '0.1.0',
      }),
    })

    render(<App />)

    expect(screen.getByText(/checking backend/i)).toBeInTheDocument()
    expect(await screen.findByText('backend healthy')).toBeInTheDocument()
    expect(fetch).toHaveBeenCalledWith('/health')
  })

  it('shows "backend unavailable" when the request fails', async () => {
    fetch.mockRejectedValueOnce(new Error('network down'))

    render(<App />)

    expect(await screen.findByText('backend unavailable')).toBeInTheDocument()
  })
})
