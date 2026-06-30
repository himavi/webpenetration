import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'

import FindingsList from './FindingsList.jsx'

const findings = [
  { id: 1, engine: 'nuclei', vuln_type: 'tech', severity: 'info', title: 'Tech detected' },
  {
    id: 2,
    engine: 'zap',
    vuln_type: 'xss',
    severity: 'high',
    title: 'Reflected XSS',
    cwe_id: 'CWE-79',
    explanation: 'XSS lets an attacker run scripts in the victim browser.',
    impact: 'Session theft and account takeover.',
    ai_remediation: 'Encode output and apply a CSP.',
  },
]

describe('FindingsList', () => {
  it('renders findings with a heading count', () => {
    render(<FindingsList findings={findings} />)
    expect(screen.getByText('Findings (2)')).toBeInTheDocument()
    expect(screen.getByText('Reflected XSS')).toBeInTheDocument()
    expect(screen.getByText('Tech detected')).toBeInTheDocument()
  })

  it('shows the AI explanation, impact and fix when present', () => {
    render(<FindingsList findings={findings} />)
    expect(screen.getByText(/lets an attacker run scripts/i)).toBeInTheDocument()
    expect(screen.getByText(/session theft/i)).toBeInTheDocument()
    expect(screen.getByText(/apply a csp/i)).toBeInTheDocument()
  })

  it('shows "of total" when a filtered subset is passed', () => {
    render(<FindingsList findings={[findings[1]]} total={2} />)
    expect(screen.getByText('Findings (1 of 2)')).toBeInTheDocument()
  })

  it('shows an empty message when no findings match', () => {
    render(<FindingsList findings={[]} />)
    expect(screen.getByText(/no findings match/i)).toBeInTheDocument()
  })

  it('renders nothing before findings are loaded', () => {
    const { container } = render(<FindingsList findings={null} />)
    expect(container).toBeEmptyDOMElement()
  })
})
