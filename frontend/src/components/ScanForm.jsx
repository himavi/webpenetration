import { useEffect, useRef, useState } from 'react'

import { SpinnerIcon } from './Icons.jsx'

const SCAN_TYPES = [
  { value: 'dast', label: 'Dynamic', tag: 'DAST', hint: 'Probe a live URL' },
  { value: 'sast', label: 'Static', tag: 'SAST', hint: 'Analyse uploaded source' },
  { value: 'both', label: 'Both', tag: 'DAST + SAST', hint: 'URL and source upload' },
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
    <form className="form scan-form" onSubmit={handleSubmit} noValidate>
      <fieldset className="field segmented-field">
        <legend className="field__label">Scan type</legend>
        <div className="segmented">
          {SCAN_TYPES.map((option) => (
            <label
              key={option.value}
              className={`segmented__option${scanType === option.value ? ' is-selected' : ''}`}
            >
              <input
                type="radio"
                name="scan_type"
                value={option.value}
                checked={scanType === option.value}
                disabled={option.disabled}
                onChange={(event) => setScanType(event.target.value)}
              />
              <span className="segmented__label">{option.label}</span>
              <span className="segmented__hint">{option.hint}</span>
              <span className="segmented__tag">{option.tag}</span>
            </label>
          ))}
        </div>
      </fieldset>

      {needsUrl && (
        <label className="field">
          <span className="field__label">Target URL</span>
          <input
            className="input input--mono"
            type="url"
            name="target"
            placeholder="https://example.com"
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            autoComplete="off"
            spellCheck={false}
          />
        </label>
      )}

      {needsFile && (
        <label className="field">
          <span className="field__label">Source code (.zip)</span>
          <input
            className="file-input"
            type="file"
            name="source"
            accept=".zip"
            ref={fileRef}
            onChange={(event) => setFile(event.target.files?.[0] ?? null)}
          />
        </label>
      )}

      <label className={`consent${authorized ? ' is-checked' : ''}`}>
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

      <button type="submit" className="button button--primary button--block" disabled={!canSubmit}>
        {busy ? <SpinnerIcon size={16} /> : null}
        {busy ? 'Starting…' : 'Start scan'}
      </button>
    </form>
  )
}
