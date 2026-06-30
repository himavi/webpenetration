import { useState } from 'react'

import { getTheme, toggleTheme } from '../theme.js'

export default function ThemeToggle() {
  const [theme, setTheme] = useState(getTheme())
  const next = theme === 'dark' ? 'light' : 'dark'

  return (
    <button
      type="button"
      className="theme-toggle"
      onClick={() => setTheme(toggleTheme())}
      aria-label={`Switch to ${next} mode`}
      title={`Switch to ${next} mode`}
    >
      {theme === 'dark' ? '\u2600' : '\u263E'}
    </button>
  )
}
