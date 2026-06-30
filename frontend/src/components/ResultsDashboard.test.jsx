import { describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import ResultsDashboard from './ResultsDashboard.jsx'

const findings = [
  { id: 1, engine: 'nuclei', vuln_type: 'tech-detect', severity: 'info', title: 'Tech' },
  { id: 2, engine: 'zap', vuln_type: 'xss', severity: 'high', title: 'XSS' },
  { id: 3, engine: 'zap', vuln_type: 'csrf', severity: 'medium', title: 'CSRF' },
]

describe('ResultsDashboard', () => {
  it('shows the severity summary counts', () => {
    render(<ResultsDashboard scan={{ id: 5 }} findings={findings} />)
    const summary = screen.getByLabelText('finding severity counts')
    expect(within(summary).getByText('high: 1')).toBeInTheDocument()
    expect(within(summary).getByText('medium: 1')).toBeInTheDocument()
    expect(within(summary).getByText('info: 1')).toBeInTheDocument()
  })

  it('filters findings by severity', async () => {
    const user = userEvent.setup()
    render(<ResultsDashboard scan={{ id: 5 }} findings={findings} />)
    expect(screen.getByText('Findings (3)')).toBeInTheDocument()

    await user.selectOptions(screen.getByLabelText('Severity'), 'high')
    expect(screen.getByText('Findings (1 of 3)')).toBeInTheDocument()
    expect(screen.getByText('XSS')).toBeInTheDocument()
    expect(screen.queryByText('CSRF')).not.toBeInTheDocument()
  })

  it('filters findings by engine', async () => {
    const user = userEvent.setup()
    render(<ResultsDashboard scan={{ id: 5 }} findings={findings} />)
    await user.selectOptions(screen.getByLabelText('Engine'), 'zap')
    expect(screen.getByText('Findings (2 of 3)')).toBeInTheDocument()
  })

  it('exposes report download links', () => {
    render(<ResultsDashboard scan={{ id: 5 }} findings={findings} />)
    expect(screen.getByRole('link', { name: 'HTML' })).toHaveAttribute(
      'href',
      '/api/scans/5/report.html',
    )
    expect(screen.getByRole('link', { name: 'PDF' })).toHaveAttribute(
      'href',
      '/api/scans/5/report.pdf',
    )
    expect(screen.getByRole('link', { name: 'JSON' })).toHaveAttribute(
      'href',
      '/api/scans/5/report.json',
    )
  })

  it('shows an empty message when the scan had no findings', () => {
    render(<ResultsDashboard scan={{ id: 5 }} findings={[]} />)
    expect(screen.getByText(/no findings were reported/i)).toBeInTheDocument()
  })
})
