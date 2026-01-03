import { signToken } from '../../../lib/auth'
import bcrypt from 'bcryptjs'
import prisma from '../../../lib/prisma'

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' })
  const { username, password } = req.body || {}
  
  if (!username || !password) return res.status(400).json({ error: 'Missing credentials' })
  
  try {
    // Find user in PostgreSQL database
    const user = await prisma.user.findUnique({
      where: { username }
    })
    
    if (!user) return res.status(401).json({ error: 'Invalid credentials' })
    
    // Compare password with hashed password
    const isPasswordValid = await bcrypt.compare(password, user.password)
    if (!isPasswordValid) return res.status(401).json({ error: 'Invalid credentials' })
    
    // Generate JWT token
    const token = signToken({ id: user.id, username: user.username, isAdmin: user.isAdmin })
    return res.status(200).json({ token, isAdmin: user.isAdmin })
  } catch (error) {
    console.error('Login error:', error)
    return res.status(500).json({ error: 'Internal server error' })
  }
}