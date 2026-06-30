// Base URL for the backend API. Empty by default so requests stay same-origin
// and flow through the Vite dev proxy (local) or the nginx proxy (docker).
// Override with VITE_API_BASE_URL to target a backend on a different origin.
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? ''

const TERMINAL_STATUSES = new Set(['done', 'failed'])

export async function fetchHealth() {
  const response = await fetch(`${API_BASE_URL}/health`)
  if (!response.ok) {
    throw new Error(`Health check failed with status ${response.status}`)
  }
  return response.json()
}

// Pull a human-readable message out of a FastAPI error body, which is either
// { detail: "..." } or { detail: [{ msg, loc }, ...] }.
function describeError(data, fallback) {
  const detail = data?.detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail) && detail.length && detail[0]?.msg) return detail[0].msg
  return fallback
}

export async function createScan({ target, scanType = 'dast', authorized }) {
  const response = await fetch(`${API_BASE_URL}/api/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target, scan_type: scanType, authorized }),
  })
  if (!response.ok) {
    let data = null
    try {
      data = await response.json()
    } catch {
      // non-JSON error body; fall back to a generic message
    }
    const error = new Error(describeError(data, `Scan request failed (${response.status})`))
    error.status = response.status
    throw error
  }
  return response.json()
}

export async function getScan(scanId) {
  const response = await fetch(`${API_BASE_URL}/api/scans/${scanId}`)
  if (!response.ok) {
    throw new Error(`Failed to load scan ${scanId} (${response.status})`)
  }
  return response.json()
}

export async function getFindings(scanId) {
  const response = await fetch(`${API_BASE_URL}/api/scans/${scanId}/findings`)
  if (!response.ok) {
    throw new Error(`Failed to load findings for scan ${scanId} (${response.status})`)
  }
  return response.json()
}

function webSocketUrl(path) {
  const origin =
    API_BASE_URL || (typeof window !== 'undefined' ? window.location.origin : 'http://localhost')
  const url = new URL(path, origin)
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:'
  return url.toString()
}

// Subscribe to live scan progress. Prefers a WebSocket; if it errors or closes
// before the scan finishes, it falls back to polling GET /api/scans/{id}.
// Returns an unsubscribe function.
export function subscribeScan(scanId, { onUpdate, onError } = {}) {
  let stopped = false
  let socket = null
  let pollTimer = null
  let polling = false

  const stop = () => {
    stopped = true
    if (socket) {
      try {
        socket.close()
      } catch {
        // ignore
      }
      socket = null
    }
    if (pollTimer) {
      clearTimeout(pollTimer)
      pollTimer = null
    }
  }

  const handle = (data) => {
    onUpdate?.(data)
    if (data && TERMINAL_STATUSES.has(data.status)) stop()
  }

  const startPolling = () => {
    if (polling || stopped) return
    polling = true
    const tick = async () => {
      if (stopped) return
      try {
        handle(await getScan(scanId))
      } catch (error) {
        onError?.(error)
      }
      if (!stopped) pollTimer = setTimeout(tick, 1000)
    }
    tick()
  }

  try {
    socket = new WebSocket(webSocketUrl(`/api/scans/${scanId}/ws`))
    socket.onmessage = (event) => {
      try {
        handle(JSON.parse(event.data))
      } catch (error) {
        onError?.(error)
      }
    }
    socket.onerror = () => {
      if (!stopped) startPolling()
    }
    socket.onclose = () => {
      if (!stopped) startPolling()
    }
  } catch {
    startPolling()
  }

  return stop
}
