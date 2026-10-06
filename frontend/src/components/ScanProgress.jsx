import { CheckCircleIcon, ClockIcon, SpinnerIcon, XCircleIcon } from './Icons.jsx'

const STATUS_LABEL = {
  queued: 'Queued',
  running: 'Running',
  done: 'Completed',
  failed: 'Failed',
}

const STATUS_ICON = {
  queued: <ClockIcon size={16} />,
  running: <SpinnerIcon size={16} />,
  done: <CheckCircleIcon size={16} />,
  failed: <XCircleIcon size={16} />,
}

export default function ScanProgress({ scan }) {
  if (!scan) return null

  const status = scan.status ?? 'queued'
  const progress = Math.max(0, Math.min(100, scan.progress ?? 0))

  return (
    <section className={`panel progress progress--${status}`} aria-live="polite">
      <div className="progress__head">
        <span className="progress__status">
          {STATUS_ICON[status] ?? STATUS_ICON.queued}
          {STATUS_LABEL[status] ?? status}
        </span>
        <span className="progress__pct">{progress}%</span>
      </div>
      <div
        className="progress__bar"
        role="progressbar"
        aria-label="scan progress"
        aria-valuenow={progress}
        aria-valuemin={0}
        aria-valuemax={100}
      >
        <div className="progress__fill" style={{ width: `${progress}%` }} />
      </div>
      {scan.message ? <p className="progress__message">{scan.message}</p> : null}
      <p className="progress__target">
        <span className="progress__target-label">target: </span>
        <code>{scan.target}</code>
      </p>
    </section>
  )
}
