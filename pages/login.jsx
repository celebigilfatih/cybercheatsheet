import { useEffect, useState } from 'react'
import { setToken, clearToken } from '../lib/client'

export default function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [message, setMessage] = useState('')

  useEffect(() => {
    setMessage('')
  }, [])

  const submit = async () => {
    setLoading(true)
    setMessage('')
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    })
    const data = await res.json()
    setLoading(false)
    if (res.ok && data.token) {
      setToken(data.token)
      window.location.href = '/'
    } else if (res.ok && data.message === 'Auth disabled') {
      setMessage('Authentication is disabled. You can use the app without login.')
    } else {
      setMessage(data.error || 'Login failed')
    }
  }

  const logout = () => {
    clearToken()
    setMessage('Logged out. Token cleared.')
  }

  return (
    <main className="mx-auto max-w-md p-6 space-y-4">
      <h1 className="text-xl font-semibold">Login</h1>
      <div className="panel p-4 space-y-3">
        <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="Username" className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-800" />
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-800" />
        <div className="flex gap-2">
          <button onClick={submit} className="btn-primary" disabled={loading}>{loading ? 'Logging in...' : 'Login'}</button>
          <button onClick={logout} className="btn-secondary">Logout</button>
        </div>
        {message && <div className="text-sm text-gray-300">{message}</div>}
      </div>
    </main>
  )
}