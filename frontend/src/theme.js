// Theme is applied to <html data-theme="..."> by an inline script in index.html
// (before render, to avoid a flash). These helpers read/flip it at runtime.
const KEY = 'aip_theme'

export function getTheme() {
  if (typeof document === 'undefined') return 'light'
  return document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light'
}

export function setTheme(theme) {
  const value = theme === 'dark' ? 'dark' : 'light'
  if (typeof document !== 'undefined') {
    document.documentElement.dataset.theme = value
  }
  try {
    localStorage.setItem(KEY, value)
  } catch {
    /* ignore */
  }
  return value
}

export function toggleTheme() {
  return setTheme(getTheme() === 'dark' ? 'light' : 'dark')
}
