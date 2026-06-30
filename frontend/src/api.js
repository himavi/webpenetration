// Base URL for the backend API. Empty by default so requests stay same-origin
// and flow through the Vite dev proxy (local) or the nginx proxy (docker).
// Override with VITE_API_BASE_URL to target a backend on a different origin.
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? ''

export async function fetchHealth() {
  const response = await fetch(`${API_BASE_URL}/health`)
  if (!response.ok) {
    throw new Error(`Health check failed with status ${response.status}`)
  }
  return response.json()
}
