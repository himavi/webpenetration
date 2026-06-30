const STATUS_LABEL = {
  queued: 'Queued',
  running: 'Running',
  done: 'Completed',
  failed: 'Failed',
}

export default function ScanProgress({ scan }) {
  if (!scan) return null

  const status = scan.status ?? 'queued'
  const progress = Math.max(0, Math.min(100, scan.progress ?? 0))

  return (
    <section className={`progress progress--${status}`} aria-live="polite">
      <div className="progress__head">
        <span className="progress__status">{STATUS_LABEL[status] ?? status}</span>
        <span className="progress__pct">{progress}%</span>
      </div>
      <div
        className="progress__bar"
        role="progressbar"
        aria-valuenow={progress}
        aria-valuemin={0}
        aria-valuemax={100}
      >
        <div className="progress__fill" style={{ width: `${progress}%` }} />
      </div>
      {scan.message ? <p className="progress__message">{scan.message}</p> : null}
      <p className="progress__target">target: {scan.target}</p>
    </section>
  )
}
