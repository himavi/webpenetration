// Base URL for the backend API. Empty by default so requests stay same-origin
// and flow through the Vite dev proxy (local) or the nginx proxy (docker).
// Override with VITE_API_BASE_URL to target a backend on a different origin.
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? ''

const TERMINAL_STATUSES = new Set(['done', 'failed'])
const TOKEN_KEY = 'aip_token'

// --- Auth token storage ---------------------------------------------------

export function getToken() {
  try {
    return localStorage.getItem(TOKEN_KEY) || ''
  } catch {
    return ''
  }
}

export function setToken(token) {
  try {
    localStorage.setItem(TOKEN_KEY, token)
  } catch {
    /* ignore */
  }
}

export function clearToken() {
  try {
    localStorage.removeItem(TOKEN_KEY)
  } catch {
    /* ignore */
  }
}

// Called whenever an authenticated request comes back 401 so the app can bounce
// the user back to the login screen.
let onUnauthorized = null
export function setUnauthorizedHandler(fn) {
  onUnauthorized = fn
}

function authHeaders(extra = {}) {
  const token = getToken()
  return token ? { ...extra, Authorization: `Bearer ${token}` } : { ...extra }
}

function handleUnauthorized() {
  clearToken()
  onUnauthorized?.()
}

// --- Auth endpoints (public) ----------------------------------------------

export async function fetchAuthStatus() {
  try {
    const response = await fetch(`${API_BASE_URL}/api/auth/status`)
    if (!response.ok) return { auth_required: false }
    return response.json()
  } catch {
    return { auth_required: false }
  }
}

export async function login(username, password) {
  const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  })
  if (!response.ok) {
    let data = null
    try {
      data = await response.json()
    } catch {
      /* ignore */
    }
    throw new Error(describeError(data, 'Invalid username or password'))
  }
  const data = await response.json()
  setToken(data.token)
  return data
}

// --- App API ---------------------------------------------------------------

export async function fetchHealth() {
  const response = await fetch(`${API_BASE_URL}/health`)
  if (!response.ok) {
    throw new Error(`Health check failed with status ${response.status}`)
  }
  return response.json()
}

export async function fetchConfig() {
  const response = await fetch(`${API_BASE_URL}/api/config`, { headers: authHeaders() })
  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Not authenticated')
  }
  if (!response.ok) return { demo_mode: false, demo_target: null }
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

export async function createScan({ target, scanType = 'dast', authorized, file = null }) {
  // If a file is provided, use the multipart upload endpoint.
  if (file) {
    const formData = new FormData()
    formData.append('file', file)
    formData.append('target', target)
    formData.append('scan_type', scanType)
    formData.append('authorized', String(authorized))
    const response = await fetch(`${API_BASE_URL}/api/scans/upload`, {
      method: 'POST',
      headers: authHeaders(),
      body: formData,
    })
    if (response.status === 401) {
      handleUnauthorized()
      throw new Error('Not authenticated')
    }
    if (!response.ok) {
      let data = null
      try { data = await response.json() } catch { /* ignore */ }
      const error = new Error(describeError(data, `Upload failed (${response.status})`))
      error.status = response.status
      throw error
    }
    return response.json()
  }

  const response = await fetch(`${API_BASE_URL}/api/scans`, {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ target, scan_type: scanType, authorized }),
  })
  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Not authenticated')
  }
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
  const response = await fetch(`${API_BASE_URL}/api/scans/${scanId}`, { headers: authHeaders() })
  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Not authenticated')
  }
  if (!response.ok) {
    throw new Error(`Failed to load scan ${scanId} (${response.status})`)
  }
  return response.json()
}

export async function getFindings(scanId) {
  const response = await fetch(`${API_BASE_URL}/api/scans/${scanId}/findings`, {
    headers: authHeaders(),
  })
  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Not authenticated')
  }
  if (!response.ok) {
    throw new Error(`Failed to load findings for scan ${scanId} (${response.status})`)
  }
  return response.json()
}

// Direct download URL for a generated report (html | pdf | json). The token is
// passed as a query param since these are opened as plain links (no headers).
export function reportUrl(scanId, format) {
  const token = getToken()
  const query = token ? `?token=${encodeURIComponent(token)}` : ''
  return `${API_BASE_URL}/api/scans/${scanId}/report.${format}${query}`
}

function webSocketUrl(path) {
  const origin =
    API_BASE_URL || (typeof window !== 'undefined' ? window.location.origin : 'http://localhost')
  const url = new URL(path, origin)
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:'
  const token = getToken()
  if (token) url.searchParams.set('token', token)
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
