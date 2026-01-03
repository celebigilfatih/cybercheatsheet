import { useEffect, useState } from 'react'
import { setToken, clearToken, getToken } from '../lib/client'
import { useLanguage } from '../lib/LanguageContext'

export default function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [message, setMessage] = useState('')
  const [isLoggedIn, setIsLoggedIn] = useState(false)
  const { t } = useLanguage()

  useEffect(() => {
    setIsLoggedIn(!!getToken())
  }, [])

  const submit = async () => {
    setLoading(true)
    setMessage('')
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      })
      const data = await res.json()
      setLoading(false)
      if (res.ok && data.token) {
        setToken(data.token)
        setIsLoggedIn(true)
        setMessage('Login successful!')
        setTimeout(() => {
          window.location.href = '/'
        }, 1000)
      } else {
        setMessage(data.error || 'Login failed')
      }
    } catch (error) {
      setLoading(false)
      setMessage(error.message || 'An error occurred')
    }
  }

  const logout = () => {
    clearToken()
    setIsLoggedIn(false)
    setMessage('Logged out successfully')
  }

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !loading) {
      submit()
    }
  }

  // Auto-fill credentials for demo
  const fillDemoCredentials = () => {
    setUsername('admin')
    setPassword('admin123')
  }

  return (
    <main className="mx-auto max-w-md p-6 space-y-4 mt-8">
      <h1 className="text-2xl font-semibold">Login</h1>
      
      {/* Default Credentials Info */}
      <div className="panel p-4 bg-blue-900 text-blue-200 border border-blue-700">
        <p className="text-sm font-semibold mb-2">Default Credentials:</p>
        <p className="text-sm">Username: <code className="bg-blue-800 px-2 py-1 rounded">admin</code></p>
        <p className="text-sm">Password: <code className="bg-blue-800 px-2 py-1 rounded">admin123</code></p>
        <button 
          onClick={fillDemoCredentials}
          className="btn-secondary mt-3 w-full text-xs"
        >
          Auto-fill Credentials
        </button>
      </div>

      <div className="panel p-6 space-y-4">
        {isLoggedIn ? (
          <>
            <p className="text-green-400">You are already logged in</p>
            <button onClick={logout} className="btn-primary w-full">Logout</button>
          </>
        ) : (
          <>
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              onKeyPress={handleKeyPress}
              placeholder="Username"
              className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-800 text-white"
              disabled={loading}
              autoComplete="username"
            />
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyPress={handleKeyPress}
              placeholder="Password"
              className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-800 text-white"
              disabled={loading}
              autoComplete="current-password"
            />
            <button
              onClick={submit}
              className="btn-primary w-full"
              disabled={loading || !username || !password}
            >
              {loading ? 'Logging in...' : 'Login'}
            </button>
          </>
        )}
        {message && (
          <div className={`text-sm p-3 rounded ${
            message.includes('successful') || message.includes('already')
              ? 'bg-green-900 text-green-200'
              : 'bg-red-900 text-red-200'
          }`}>
            {message}
          </div>
        )}
      </div>
    </main>
  )
}
