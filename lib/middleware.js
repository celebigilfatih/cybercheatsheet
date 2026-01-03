import { verifyToken } from './auth'

export function withAuth(handler) {
  return async (req, res) => {
    const authHeader = req.headers.authorization || ''
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null
    
    if (!token) {
      return res.status(401).json({ error: 'Unauthorized' })
    }
    
    try {
      const decoded = verifyToken(token)
      req.user = decoded
      return handler(req, res)
    } catch (error) {
      return res.status(401).json({ error: 'Invalid token' })
    }
  }
}

export function withAdminAuth(handler) {
  return async (req, res) => {
    const authHeader = req.headers.authorization || ''
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null
    
    if (!token) {
      return res.status(401).json({ error: 'Unauthorized' })
    }
    
    try {
      const decoded = verifyToken(token)
      if (!decoded.isAdmin) {
        return res.status(403).json({ error: 'Admin privileges required' })
      }
      req.user = decoded
      return handler(req, res)
    } catch (error) {
      return res.status(401).json({ error: 'Invalid token' })
    }
  }
}
