import dbConnect from '../../../lib/dbConnect'
import Category from '../../../models/Category'
import { requireAuth } from '../../../lib/auth'

export default async function handler(req, res) {
  await dbConnect()
  if (req.method === 'GET') {
    const categories = await Category.find({}).sort({ name: 1 })
    return res.status(200).json({ categories })
  }
  if (req.method === 'POST') {
    if (!requireAuth(req, res)) return
    const { name, description } = req.body || {}
    if (!name) return res.status(400).json({ error: 'Name is required' })
    try {
      const category = await Category.create({ name, description })
      return res.status(201).json({ category })
    } catch (e) {
      return res.status(400).json({ error: e.message })
    }
  }
  return res.status(405).json({ error: 'Method not allowed' })
}