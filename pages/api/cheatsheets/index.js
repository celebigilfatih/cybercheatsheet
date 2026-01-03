import prisma from '../../../lib/prisma'
import { withAdminAuth } from '../../../lib/middleware'
import sanitizeHtml from 'sanitize-html'

async function handler(req, res) {
  if (req.method === 'GET') {
    const { q, category, tag } = req.query
    const where = {}
    if (category) where.categoryId = parseInt(category, 10)
    if (tag) where.tags = { hasSome: [tag] }

    try {
      let cheatsheets = []
      if (q) {
        // Simple text search across title and description fields
        cheatsheets = await prisma.cheatsheet.findMany({
          where: {
            ...where,
            OR: [
              { titleEn: { contains: q, mode: 'insensitive' } },
              { titleTr: { contains: q, mode: 'insensitive' } },
              { descEn: { contains: q, mode: 'insensitive' } },
              { descTr: { contains: q, mode: 'insensitive' } }
            ]
          },
          include: { category: true },
          orderBy: { updatedAt: 'desc' }
        })
      } else {
        cheatsheets = await prisma.cheatsheet.findMany({
          where,
          include: { category: true },
          orderBy: { updatedAt: 'desc' }
        })
      }
      return res.status(200).json({ cheatsheets })
    } catch (error) {
      console.error('Error fetching cheatsheets:', error)
      return res.status(500).json({ error: 'Internal server error' })
    }
  }

  if (req.method === 'POST') {
    return withAdminAuth(createCheatsheet)(req, res)
  }

  return res.status(405).json({ error: 'Method not allowed' })
}

async function createCheatsheet(req, res) {
  const { titleEn, titleTr, descriptionEn, descriptionTr, tags = [], links = [], categoryId } = req.body || {}
  if (!titleEn || !titleTr || !categoryId) {
    return res.status(400).json({ error: 'Title (en/tr) and category are required' })
  }
  
  try {
    const sanitizedDescEn = sanitizeHtml(descriptionEn || '', { allowedTags: false, allowedAttributes: false })
    const sanitizedDescTr = sanitizeHtml(descriptionTr || '', { allowedTags: false, allowedAttributes: false })
    
    const cheatsheet = await prisma.cheatsheet.create({
      data: {
        titleEn,
        titleTr,
        descEn: sanitizedDescEn,
        descTr: sanitizedDescTr,
        tags,
        links,
        categoryId: parseInt(categoryId, 10)
      },
      include: { category: true }
    })
    return res.status(201).json({ cheatsheet })
  } catch (error) {
    console.error('Error creating cheatsheet:', error)
    return res.status(400).json({ error: error.message })
  }
}

export default handler