import { afterEach, describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import ThemeToggle from './components/ThemeToggle.jsx'

describe('theme toggle', () => {
  afterEach(() => {
    localStorage.clear()
    delete document.documentElement.dataset.theme
  })

  it('defaults to light and switches to dark on click', async () => {
    const user = userEvent.setup()
    render(<ThemeToggle />)

    const toDark = screen.getByRole('button', { name: /switch to dark mode/i })
    await user.click(toDark)

    expect(document.documentElement.dataset.theme).toBe('dark')
    expect(localStorage.getItem('aip_theme')).toBe('dark')
    expect(screen.getByRole('button', { name: /switch to light mode/i })).toBeInTheDocument()
  })
})
