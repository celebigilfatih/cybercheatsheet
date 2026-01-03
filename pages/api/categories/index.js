import prisma from '../../../lib/prisma'
import { withAdminAuth } from '../../../lib/middleware'

async function handler(req, res) {
  if (req.method === 'GET') {
    try {
      const categories = await prisma.category.findMany({
        orderBy: { nameTr: 'asc' }
      })
      return res.status(200).json({ categories })
    } catch (error) {
      console.error('Error fetching categories:', error)
      return res.status(500).json({ error: 'Internal server error' })
    }
  }
  
  if (req.method === 'POST') {
    return withAdminAuth(createCategory)(req, res)
  }
  
  return res.status(405).json({ error: 'Method not allowed' })
}

async function createCategory(req, res) {
  const { nameEn, nameTr, descEn = '', descTr = '' } = req.body || {}
  if (!nameEn || !nameTr) return res.status(400).json({ error: 'Name (en/tr) is required' })
  
  try {
    const category = await prisma.category.create({
      data: { nameEn, nameTr, descEn, descTr }
    })
    return res.status(201).json({ category })
  } catch (error) {
    console.error('Error creating category:', error)
    return res.status(400).json({ error: error.message })
  }
}

export default handler