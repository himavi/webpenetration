import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import ScanForm from './ScanForm.jsx'

describe('ScanForm consent gate', () => {
  it('keeps the submit button disabled until target and consent are provided', async () => {
    const user = userEvent.setup()
    render(<ScanForm onSubmit={vi.fn()} />)

    const button = screen.getByRole('button', { name: /start scan/i })
    expect(button).toBeDisabled()

    await user.type(screen.getByLabelText(/target url/i), 'https://example.com')
    expect(button).toBeDisabled() // target set, but consent still unchecked

    await user.click(screen.getByLabelText(/authorized to test/i))
    expect(button).toBeEnabled()
  })

  it('does not submit without consent, and submits with it', async () => {
    const user = userEvent.setup()
    const onSubmit = vi.fn()
    render(<ScanForm onSubmit={onSubmit} />)

    await user.type(screen.getByLabelText(/target url/i), 'https://example.com')
    await user.click(screen.getByRole('button', { name: /start scan/i }))
    expect(onSubmit).not.toHaveBeenCalled()

    await user.click(screen.getByLabelText(/authorized to test/i))
    await user.click(screen.getByRole('button', { name: /start scan/i }))
    expect(onSubmit).toHaveBeenCalledWith({
      target: 'https://example.com',
      scanType: 'dast',
      authorized: true,
    })
  })
})
