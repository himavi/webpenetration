import { useState } from 'react'

import { getTheme, toggleTheme } from '../theme.js'
import { MoonIcon, SunIcon } from './Icons.jsx'

export default function ThemeToggle() {
  const [theme, setTheme] = useState(getTheme())
  const next = theme === 'dark' ? 'light' : 'dark'

  return (
    <button
      type="button"
      className="icon-button theme-toggle"
      onClick={() => setTheme(toggleTheme())}
      aria-label={`Switch to ${next} mode`}
      title={`Switch to ${next} mode`}
    >
      {theme === 'dark' ? <SunIcon size={18} /> : <MoonIcon size={18} />}
    </button>
  )
}
