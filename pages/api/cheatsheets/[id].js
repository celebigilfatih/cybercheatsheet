import dbConnect from '../../../lib/dbConnect'
import Cheatsheet from '../../../models/Cheatsheet'
import sanitizeHtml from 'sanitize-html'
import { requireAuth } from '../../../lib/auth'

export default async function handler(req, res) {
  await dbConnect()
  const { id } = req.query
  if (req.method === 'GET') {
    const cheatsheet = await Cheatsheet.findById(id)
    if (!cheatsheet) return res.status(404).json({ error: 'Not found' })
    return res.status(200).json({ cheatsheet })
  }
  if (req.method === 'PUT') {
    if (!requireAuth(req, res)) return
    let body = req.body || {}
    if (typeof body === 'string') {
      try {
        body = JSON.parse(body)
      } catch (e) {
        body = {}
      }
    }
    const { title, description, tags, links, category } = body
    
    // Handle bilingual description {tr: "...", en: "..."} or string
    let sanitized
    if (description && typeof description === 'object' && (description.tr || description.en)) {
      sanitized = {
        tr: sanitizeHtml(description.tr || '', { allowedTags: false, allowedAttributes: false }),
        en: sanitizeHtml(description.en || '', { allowedTags: false, allowedAttributes: false })
      }
    } else {
      sanitized = sanitizeHtml(description || '', { allowedTags: false, allowedAttributes: false })
    }
    
    const cheatsheet = await Cheatsheet.findByIdAndUpdate(
      id,
      { title, description: sanitized, tags, links, category },
      { new: true }
    )
    return res.status(200).json({ cheatsheet })
  }
  if (req.method === 'DELETE') {
    if (!requireAuth(req, res)) return
    await Cheatsheet.findByIdAndDelete(id)
    return res.status(204).end()
  }
  return res.status(405).json({ error: 'Method not allowed' })
}