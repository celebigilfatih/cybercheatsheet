export function getToken() {
  try {
    const token = localStorage.getItem('token')
    if (!token || token === 'null' || token === 'undefined') return null
    return token
  } catch {
    return null
  }
}

export function setToken(token) {
  try {
    if (token) localStorage.setItem('token', token)
  } catch {}
}

export function clearToken() {
  try {
    localStorage.removeItem('token')
  } catch {}
}

export async function authFetch(url, options = {}) {
  const token = getToken()
  const headers = { ...(options.headers || {}) }
  if (token) headers['Authorization'] = `Bearer ${token}`
  return fetch(url, { ...options, headers })
}