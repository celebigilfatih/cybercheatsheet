#!/usr/bin/env node
/**
 * Migration script: MongoDB to PostgreSQL
 * 1. Creates PostgreSQL tables
 * 2. Migrates categories and cheatsheets from MongoDB
 * 3. Creates admin user
 */
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import bcrypt from 'bcryptjs'
import { PrismaClient } from '@prisma/client'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

// Load .env.local
const envPath = path.join(__dirname, '..', '.env.local')
if (fs.existsSync(envPath)) {
  const lines = fs.readFileSync(envPath, 'utf-8').split(/\r?\n/)
  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    const idx = trimmed.indexOf('=')
    if (idx === -1) continue
    const key = trimmed.slice(0, idx).trim()
    const val = trimmed.slice(idx + 1).trim()
    if (key && !(key in process.env)) process.env[key] = val
  }
}

const prisma = new PrismaClient()

async function migrateData() {
  try {
    console.log('Starting migration to PostgreSQL...\n')
    
    // Step 1: Read MongoDB data from mdb folder
    console.log('Step 1: Reading MongoDB data...')
    const mdbPath = path.join(__dirname, '..', 'mdb')
    
    let categories = []
    let cheatsheets = []
    
    const categoriesPath = path.join(mdbPath, 'categories.json')
    if (fs.existsSync(categoriesPath)) {
      const data = JSON.parse(fs.readFileSync(categoriesPath, 'utf-8'))
      categories = data.map(cat => ({
        ...cat,
        createdAt: cat.createdAt && cat.createdAt.$date ? new Date(cat.createdAt.$date) : new Date(),
        updatedAt: cat.updatedAt && cat.updatedAt.$date ? new Date(cat.updatedAt.$date) : new Date(),
        originalId: cat._id && cat._id.$oid ? cat._id.$oid : null
      }))
      console.log(`  Loaded ${categories.length} categories`)
    }
    
    const cheatsheetsPath = path.join(mdbPath, 'cheatsheets.json')
    if (fs.existsSync(cheatsheetsPath)) {
      const data = JSON.parse(fs.readFileSync(cheatsheetsPath, 'utf-8'))
      cheatsheets = data.map(sheet => ({
        ...sheet,
        createdAt: sheet.createdAt && sheet.createdAt.$date ? new Date(sheet.createdAt.$date) : new Date(),
        updatedAt: sheet.updatedAt && sheet.updatedAt.$date ? new Date(sheet.updatedAt.$date) : new Date(),
        originalId: sheet._id && sheet._id.$oid ? sheet._id.$oid : null,
        categoryOid: sheet.category && sheet.category.$oid ? sheet.category.$oid : null
      }))
      console.log(`  Loaded ${cheatsheets.length} cheatsheets\n`)
    }
    
    // Step 2: Clear existing data
    console.log('Step 2: Clearing existing PostgreSQL data...')
    await prisma.cheatsheet.deleteMany({})
    await prisma.category.deleteMany({})
    console.log('  Cleared cheatsheets and categories\n')
    
    // Step 3: Migrate categories
    console.log('Step 3: Migrating categories to PostgreSQL...')
    const categoryMap = {} // Map original MongoDB OIDs to new PostgreSQL IDs
    
    for (const cat of categories) {
      const nameEn = cat.name && cat.name.en ? cat.name.en : cat.name
      const nameTr = cat.name && cat.name.tr ? cat.name.tr : cat.name
      
      const created = await prisma.category.create({
        data: {
          nameEn,
          nameTr,
          descEn: (cat.description && cat.description.en) || cat.description || '',
          descTr: (cat.description && cat.description.tr) || cat.description || ''
        }
      })
      
      if (cat.originalId) {
        categoryMap[cat.originalId] = created.id
      }
      
      console.log(`  Created category: ${nameTr} (ID: ${created.id})`)
    }
    console.log('')
    
    // Step 4: Migrate cheatsheets
    console.log('Step 4: Migrating cheatsheets to PostgreSQL...')
    for (const sheet of cheatsheets) {
      const categoryId = categoryMap[sheet.categoryOid]
      if (!categoryId) {
        console.warn(`  ⚠ Skipping cheatsheet: category not found`)
        continue
      }
      
      const titleEn = sheet.title && sheet.title.en ? sheet.title.en : sheet.title
      const titleTr = sheet.title && sheet.title.tr ? sheet.title.tr : sheet.title
      
      await prisma.cheatsheet.create({
        data: {
          titleEn,
          titleTr,
          descEn: (sheet.description && sheet.description.en) || sheet.description || '',
          descTr: (sheet.description && sheet.description.tr) || sheet.description || '',
          tags: Array.isArray(sheet.tags) ? sheet.tags : [],
          links: Array.isArray(sheet.links) ? sheet.links : [],
          categoryId
        }
      })
      
      console.log(`  Created cheatsheet: ${titleTr}`)
    }
    console.log('')
    
    // Step 5: Create admin user
    console.log('Step 5: Setting up admin user...')
    const adminUsername = process.env.ADMIN_USER || 'admin'
    const adminPassword = process.env.ADMIN_PASS || 'admin123'
    
    // Check if admin user already exists
    const existingAdmin = await prisma.user.findUnique({
      where: { username: adminUsername }
    })
    
    if (existingAdmin) {
      console.log(`  Admin user '${adminUsername}' already exists`)
    } else {
      const hashedPassword = await bcrypt.hash(adminPassword, 10)
      const adminUser = await prisma.user.create({
        data: {
          username: adminUsername,
          password: hashedPassword,
          isAdmin: true
        }
      })
      console.log(`  Created admin user: '${adminUser.username}' (ID: ${adminUser.id})`)
      console.log(`  ⚠ Please change the password after first login!`)
    }
    console.log('')
    
    // Summary
    const totalCategories = await prisma.category.count()
    const totalCheatsheets = await prisma.cheatsheet.count()
    const totalUsers = await prisma.user.count()
    
    console.log('✓ Migration completed successfully!')
    console.log(`  Categories: ${totalCategories}`)
    console.log(`  Cheatsheets: ${totalCheatsheets}`)
    console.log(`  Users: ${totalUsers}`)
    
  } catch (error) {
    console.error('❌ Migration failed:', error.message)
    process.exit(1)
  } finally {
    await prisma.$disconnect()
  }
}

migrateData()
