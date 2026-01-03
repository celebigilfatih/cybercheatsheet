import prisma from '../../../lib/prisma'
import { withAdminAuth } from '../../../lib/middleware'

async function handler(req, res) {
  const id = parseInt(req.query.id, 10)

  if (req.method === 'GET') {
    try {
      const category = await prisma.category.findUnique({
        where: { id }
      })
      if (!category) return res.status(404).json({ error: 'Not found' })
      return res.status(200).json({ category })
    } catch (error) {
      console.error('Error fetching category:', error)
      return res.status(500).json({ error: 'Internal server error' })
    }
  }

  if (req.method === 'PUT') {
    return withAdminAuth(updateCategory)(req, res)
  }

  if (req.method === 'DELETE') {
    return withAdminAuth(deleteCategory)(req, res)
  }

  return res.status(405).json({ error: 'Method not allowed' })
}

async function updateCategory(req, res) {
  const id = parseInt(req.query.id, 10)
  const { nameEn, nameTr, descEn, descTr } = req.body || {}

  if (!nameEn || !nameTr) {
    return res.status(400).json({ error: 'Name (en/tr) is required' })
  }

  try {
    const category = await prisma.category.update({
      where: { id },
      data: {
        nameEn,
        nameTr,
        descEn: descEn || '',
        descTr: descTr || ''
      }
    })
    return res.status(200).json({ category })
  } catch (error) {
    console.error('Error updating category:', error)
    return res.status(400).json({ error: error.message })
  }
}

async function deleteCategory(req, res) {
  const id = parseInt(req.query.id, 10)

  try {
    await prisma.category.delete({
      where: { id }
    })
    return res.status(204).end()
  } catch (error) {
    console.error('Error deleting category:', error)
    return res.status(400).json({ error: error.message })
  }
}

export default handler
