import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'

import FindingsList from './FindingsList.jsx'

const sampleFindings = [
  {
    id: 1,
    scan_id: 1,
    engine: 'nuclei',
    vuln_type: 'tech-detect',
    severity: 'info',
    title: 'Technology detected',
    location: 'https://example.com',
  },
  {
    id: 2,
    scan_id: 1,
    engine: 'nuclei',
    vuln_type: 'CVE-2021-99999',
    severity: 'critical',
    title: 'Remote code execution',
    location: 'https://example.com/api',
    cwe_id: 'CWE-77',
  },
]

describe('FindingsList', () => {
  it('renders findings with most severe first', () => {
    render(<FindingsList findings={sampleFindings} />)
    expect(screen.getByText('Findings (2)')).toBeInTheDocument()

    const titles = screen.getAllByText(/Technology detected|Remote code execution/)
    expect(titles[0]).toHaveTextContent('Remote code execution') // critical sorted above info
  })

  it('shows an empty message when there are no findings', () => {
    render(<FindingsList findings={[]} />)
    expect(screen.getByText(/no findings reported/i)).toBeInTheDocument()
  })

  it('shows a loading message and renders nothing before a scan', () => {
    const { rerender, container } = render(<FindingsList findings={null} loading />)
    expect(screen.getByText(/loading findings/i)).toBeInTheDocument()

    rerender(<FindingsList findings={null} loading={false} />)
    expect(container).toBeEmptyDOMElement()
  })
})
