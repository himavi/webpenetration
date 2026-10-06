import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

import App from './App.jsx'
import './index.css'

// The theme toggle now lives inside the app's top bar (rendered by App on every
// screen, including login), so it no longer floats over the page here.
createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
