import { useState } from 'react'

const SCAN_TYPES = [
  { value: 'dast', label: 'Dynamic — live URL (DAST)' },
  { value: 'sast', label: 'Static — source upload (coming soon)', disabled: true },
]

export default function ScanForm({ onSubmit, busy = false }) {
  const [target, setTarget] = useState('')
  const [scanType, setScanType] = useState('dast')
  const [authorized, setAuthorized] = useState(false)

  const canSubmit = target.trim().length > 0 && authorized && !busy

  const handleSubmit = (event) => {
    event.preventDefault()
    if (!canSubmit) return
    onSubmit({ target: target.trim(), scanType, authorized })
  }

  return (
    <form className="scan-form" onSubmit={handleSubmit} noValidate>
      <label className="field">
        <span className="field__label">Target URL</span>
        <input
          type="url"
          name="target"
          placeholder="https://example.com"
          value={target}
          onChange={(event) => setTarget(event.target.value)}
          autoComplete="off"
        />
      </label>

      <label className="field">
        <span className="field__label">Scan type</span>
        <select value={scanType} onChange={(event) => setScanType(event.target.value)}>
          {SCAN_TYPES.map((option) => (
            <option key={option.value} value={option.value} disabled={option.disabled}>
              {option.label}
            </option>
          ))}
        </select>
      </label>

      <label className="consent">
        <input
          type="checkbox"
          name="authorized"
          checked={authorized}
          onChange={(event) => setAuthorized(event.target.checked)}
        />
        <span>
          I am authorized to test this target and take responsibility for this scan.
        </span>
      </label>

      <button type="submit" className="button" disabled={!canSubmit}>
        {busy ? 'Starting…' : 'Start scan'}
      </button>
    </form>
  )
}
