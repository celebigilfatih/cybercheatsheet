import { signToken } from '../../../lib/auth'
import bcrypt from 'bcryptjs'

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' })
  const { username, password } = req.body || {}
  const adminUser = process.env.ADMIN_USER
  const adminPass = process.env.ADMIN_PASS
  const enforce = Boolean(adminUser && adminPass)
  if (!enforce) {
    return res.status(200).json({ message: 'Auth disabled', token: null })
  }
  if (!username || !password) return res.status(400).json({ error: 'Missing credentials' })
  const matchUser = username === adminUser
  const matchPass = bcrypt.compareSync(password, bcrypt.hashSync(adminPass, 8))
  if (!matchUser || !matchPass) return res.status(401).json({ error: 'Invalid credentials' })
  const token = signToken({ username })
  return res.status(200).json({ token })
}