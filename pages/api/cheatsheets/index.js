import dbConnect from '../../../lib/dbConnect'
import Cheatsheet from '../../../models/Cheatsheet'
import sanitizeHtml from 'sanitize-html'
import { requireAuth } from '../../../lib/auth'

export default async function handler(req, res) {
  await dbConnect()
  if (req.method === 'GET') {
    const { q, category, tag } = req.query
    const filter = {}
    if (category) filter.category = category
    if (tag) filter.tags = { $in: [tag] }

    let cheatsheets = []
    if (q) {
      cheatsheets = await Cheatsheet.find({ $text: { $search: q }, ...filter })
        .sort({ updatedAt: -1 })
        .lean()
    } else {
      cheatsheets = await Cheatsheet.find(filter).sort({ updatedAt: -1 }).lean()
    }
    return res.status(200).json({ cheatsheets })
  }

  if (req.method === 'POST') {
    if (!requireAuth(req, res)) return
    const { title, description, tags = [], links = [], category } = req.body || {}
    if (!title || !category) return res.status(400).json({ error: 'Title and category are required' })
    
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
    
    try {
      const cheatsheet = await Cheatsheet.create({ title, description: sanitized, tags, links, category })
      return res.status(201).json({ cheatsheet })
    } catch (e) {
      return res.status(400).json({ error: e.message })
    }
  }

  return res.status(405).json({ error: 'Method not allowed' })
}