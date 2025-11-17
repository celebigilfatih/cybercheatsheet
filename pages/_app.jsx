import '../styles/globals.css'
import { useEffect, useState } from 'react'
import { getToken, clearToken } from '../lib/client'

export default function App({ Component, pageProps }) {
  const [dark, setDark] = useState(true)

  useEffect(() => {
    const saved = localStorage.getItem('theme')
    const isDark = saved ? saved === 'dark' : true
    setDark(isDark)
    document.documentElement.classList.toggle('dark', isDark)
  }, [])

  const toggle = () => {
    const next = !dark
    setDark(next)
    localStorage.setItem('theme', next ? 'dark' : 'light')
    document.documentElement.classList.toggle('dark', next)
  }

  const logout = () => {
    clearToken()
    alert('Logged out')
  }

  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-50 border-b border-gray-800 bg-cyber-panel">
        <div className="mx-auto max-w-7xl px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-cyber-accent font-semibold">CyberSec Cheatsheet</span>
            <span className="text-xs text-gray-400">Organize your security docs</span>
          </div>
          <div className="flex items-center gap-2">
            <a href="/categories" className="btn-secondary">Categories</a>
            <a href="/login" className="btn-secondary">Login</a>
            <button onClick={logout} className="btn-secondary">Logout</button>
            <button onClick={toggle} className="btn-secondary">{dark ? 'Light' : 'Dark'} Mode</button>
          </div>
        </div>
      </header>
      <Component {...pageProps} />
    </div>
  )
}
