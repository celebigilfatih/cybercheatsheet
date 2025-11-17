import dbConnect from '../../../lib/dbConnect'
import Category from '../../../models/Category'
import { requireAuth } from '../../../lib/auth'

export default async function handler(req, res) {
  await dbConnect()
  const { id } = req.query
  if (req.method === 'GET') {
    const category = await Category.findById(id)
    if (!category) return res.status(404).json({ error: 'Not found' })
    return res.status(200).json({ category })
  }
  if (req.method === 'PUT') {
    if (!requireAuth(req, res)) return
    const { name, description } = req.body || {}
    const category = await Category.findByIdAndUpdate(id, { name, description }, { new: true })
    return res.status(200).json({ category })
  }
  if (req.method === 'DELETE') {
    if (!requireAuth(req, res)) return
    await Category.findByIdAndDelete(id)
    return res.status(204).end()
  }
  return res.status(405).json({ error: 'Method not allowed' })
}