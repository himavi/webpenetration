import { useEffect, useRef, useState } from 'react'

const SCAN_TYPES = [
  { value: 'dast', label: 'Dynamic — live URL (DAST)' },
  { value: 'sast', label: 'Static — source upload (SAST)' },
  { value: 'both', label: 'Both — URL + source upload' },
]

export default function ScanForm({ onSubmit, busy = false, demoTarget = null }) {
  const [target, setTarget] = useState(demoTarget || '')
  const [scanType, setScanType] = useState('dast')
  const [authorized, setAuthorized] = useState(false)
  const [file, setFile] = useState(null)
  const fileRef = useRef(null)

  // Update target if demoTarget arrives after initial render.
  useEffect(() => {
    if (demoTarget && !target) setTarget(demoTarget)
  }, [demoTarget])

  const needsUrl = scanType === 'dast' || scanType === 'both'
  const needsFile = scanType === 'sast' || scanType === 'both'

  const canSubmit =
    authorized &&
    !busy &&
    (needsUrl ? target.trim().length > 0 : true) &&
    (needsFile ? file != null : true)

  const handleSubmit = (event) => {
    event.preventDefault()
    if (!canSubmit) return
    onSubmit({
      target: target.trim() || 'uploaded-source',
      scanType,
      authorized,
      file: needsFile ? file : null,
    })
  }

  return (
    <form className="scan-form" onSubmit={handleSubmit} noValidate>
      {needsUrl && (
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
      )}

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

      {needsFile && (
        <label className="field">
          <span className="field__label">Source code (.zip)</span>
          <input
            type="file"
            name="source"
            accept=".zip"
            ref={fileRef}
            onChange={(event) => setFile(event.target.files?.[0] ?? null)}
          />
        </label>
      )}

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
