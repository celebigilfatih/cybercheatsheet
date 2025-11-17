import jwt from 'jsonwebtoken'

export function signToken(payload) {
  const secret = process.env.JWT_SECRET || 'dev-secret-change-me'
  return jwt.sign(payload, secret, { expiresIn: '7d' })
}

export function verifyToken(token) {
  const secret = process.env.JWT_SECRET || 'dev-secret-change-me'
  return jwt.verify(token, secret)
}

export function requireAuth(req, res) {
  // Optional auth: only enforce when ADMIN_USER and ADMIN_PASS are set
  const enforce = Boolean(process.env.ADMIN_USER && process.env.ADMIN_PASS)
  if (!enforce) return true

  const authHeader = req.headers.authorization || ''
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null
  if (!token) {
    res.status(401).json({ error: 'Unauthorized' })
    return false
  }
  try {
    verifyToken(token)
    return true
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' })
    return false
  }
}