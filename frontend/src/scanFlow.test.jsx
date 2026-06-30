import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import App from './App.jsx'

// Minimal fake WebSocket whose messages the test drives explicitly.
class FakeWebSocket {
  static instances = []

  constructor(url) {
    this.url = url
    this.readyState = 0
    this.onopen = null
    this.onmessage = null
    this.onerror = null
    this.onclose = null
    FakeWebSocket.instances.push(this)
  }

  emit(payload) {
    this.onmessage?.({ data: JSON.stringify(payload) })
  }

  close() {
    this.readyState = 3
    this.onclose?.({})
  }
}

function fakeFetch() {
  return vi.fn(async (url, options) => {
    if (typeof url === 'string' && url.endsWith('/health')) {
      return { ok: true, json: async () => ({ status: 'ok', service: 'x', version: '0.3.0' }) }
    }
    if (typeof url === 'string' && url.endsWith('/api/scans') && options?.method === 'POST') {
      return {
        ok: true,
        json: async () => ({
          id: 1,
          target: 'https://example.com',
          scan_type: 'dast',
          status: 'queued',
          progress: 0,
          message: 'queued',
        }),
      }
    }
    return { ok: false, status: 404, json: async () => ({}) }
  })
}

describe('scan submission flow', () => {
  beforeEach(() => {
    FakeWebSocket.instances = []
    vi.stubGlobal('fetch', fakeFetch())
    vi.stubGlobal('WebSocket', FakeWebSocket)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  it('submits with consent and shows live progress through to completion', async () => {
    const user = userEvent.setup()
    render(<App />)

    expect(await screen.findByText('backend healthy')).toBeInTheDocument()

    await user.type(screen.getByLabelText(/target url/i), 'https://example.com')
    await user.click(screen.getByLabelText(/authorized to test/i))
    await user.click(screen.getByRole('button', { name: /start scan/i }))

    // Progress UI appears once the scan is created.
    expect(await screen.findByRole('progressbar')).toBeInTheDocument()
    await waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1))
    const socket = FakeWebSocket.instances[0]

    act(() =>
      socket.emit({
        id: 1,
        target: 'https://example.com',
        scan_type: 'dast',
        status: 'running',
        progress: 55,
        message: 'active vulnerability checks',
      }),
    )
    expect(await screen.findByText('55%')).toBeInTheDocument()
    expect(screen.getByText(/running/i)).toBeInTheDocument()

    act(() =>
      socket.emit({
        id: 1,
        target: 'https://example.com',
        scan_type: 'dast',
        status: 'done',
        progress: 100,
        message: 'scan complete',
      }),
    )
    expect(await screen.findByText('100%')).toBeInTheDocument()
    expect(screen.getByText(/completed/i)).toBeInTheDocument()
  })
})
