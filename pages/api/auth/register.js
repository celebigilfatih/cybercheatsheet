import bcrypt from 'bcryptjs'
import prisma from '../../../lib/prisma'
import { signToken } from '../../../lib/auth'

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' })
  
  const { username, password, isAdmin = false } = req.body || {}
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' })
  }
  
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' })
  }
  
  try {
    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { username }
    })
    
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' })
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10)
    
    // Create user
    const user = await prisma.user.create({
      data: {
        username,
        password: hashedPassword,
        isAdmin
      }
    })
    
    // Generate JWT token
    const token = signToken({ id: user.id, username: user.username, isAdmin: user.isAdmin })
    
    return res.status(201).json({ 
      message: 'User registered successfully',
      token,
      user: { id: user.id, username: user.username, isAdmin: user.isAdmin }
    })
  } catch (error) {
    console.error('Registration error:', error)
    return res.status(500).json({ error: 'Internal server error' })
  }
}
