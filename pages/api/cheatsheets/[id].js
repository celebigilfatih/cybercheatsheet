import prisma from '../../../lib/prisma'
import { withAdminAuth } from '../../../lib/middleware'
import sanitizeHtml from 'sanitize-html'

async function handler(req, res) {
  const id = parseInt(req.query.id, 10)
  
  if (req.method === 'GET') {
    try {
      const cheatsheet = await prisma.cheatsheet.findUnique({
        where: { id },
        include: { category: true }
      })
      if (!cheatsheet) return res.status(404).json({ error: 'Not found' })
      return res.status(200).json({ cheatsheet })
    } catch (error) {
      console.error('Error fetching cheatsheet:', error)
      return res.status(500).json({ error: 'Internal server error' })
    }
  }
  
  if (req.method === 'PUT') {
    return withAdminAuth(updateCheatsheet)(req, res)
  }
  
  if (req.method === 'DELETE') {
    return withAdminAuth(deleteCheatsheet)(req, res)
  }
  
  return res.status(405).json({ error: 'Method not allowed' })
}

async function updateCheatsheet(req, res) {
  const id = parseInt(req.query.id, 10)
  let body = req.body || {}
  if (typeof body === 'string') {
    try {
      body = JSON.parse(body)
    } catch (e) {
      body = {}
    }
  }
  const { titleEn, titleTr, descriptionEn, descriptionTr, tags, links, categoryId } = body
  
  try {
    const sanitizedDescEn = descriptionEn ? sanitizeHtml(descriptionEn, { allowedTags: false, allowedAttributes: false }) : undefined
    const sanitizedDescTr = descriptionTr ? sanitizeHtml(descriptionTr, { allowedTags: false, allowedAttributes: false }) : undefined
    
    const updateData = {}
    if (titleEn !== undefined) updateData.titleEn = titleEn
    if (titleTr !== undefined) updateData.titleTr = titleTr
    if (sanitizedDescEn !== undefined) updateData.descEn = sanitizedDescEn
    if (sanitizedDescTr !== undefined) updateData.descTr = sanitizedDescTr
    if (tags !== undefined) updateData.tags = tags
    if (links !== undefined) updateData.links = links
    if (categoryId !== undefined) updateData.categoryId = parseInt(categoryId, 10)
    
    const cheatsheet = await prisma.cheatsheet.update({
      where: { id },
      data: updateData,
      include: { category: true }
    })
    return res.status(200).json({ cheatsheet })
  } catch (error) {
    console.error('Error updating cheatsheet:', error)
    return res.status(400).json({ error: error.message })
  }
}

async function deleteCheatsheet(req, res) {
  const id = parseInt(req.query.id, 10)
  
  try {
    await prisma.cheatsheet.delete({
      where: { id }
    })
    return res.status(204).end()
  } catch (error) {
    console.error('Error deleting cheatsheet:', error)
    return res.status(400).json({ error: error.message })
  }
}

export default handler