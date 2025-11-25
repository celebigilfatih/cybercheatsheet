import mongoose from 'mongoose'

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:33017/cybersheet'

async function migrate() {
  try {
    await mongoose.connect(MONGODB_URI)
    console.log('Connected to MongoDB')

    const db = mongoose.connection.db
    
    // Migrate Cheatsheets
    const cheatsheets = await db.collection('cheatsheets').find({}).toArray()
    console.log(`Found ${cheatsheets.length} cheatsheets to migrate`)
    
    for (const sheet of cheatsheets) {
      // Check if already migrated
      if (sheet.title && typeof sheet.title === 'object' && sheet.title.tr) {
        console.log(`Skipping already migrated cheatsheet: ${sheet._id}`)
        continue
      }
      
      const update = {
        title: {
          tr: sheet.title || 'Başlıksız',
          en: sheet.title || 'Untitled'
        },
        description: {
          tr: sheet.description || '',
          en: sheet.description || ''
        }
      }
      
      await db.collection('cheatsheets').updateOne(
        { _id: sheet._id },
        { $set: update }
      )
      console.log(`Migrated cheatsheet: ${sheet.title}`)
    }
    
    // Migrate Categories
    const categories = await db.collection('categories').find({}).toArray()
    console.log(`Found ${categories.length} categories to migrate`)
    
    for (const cat of categories) {
      // Check if already migrated
      if (cat.name && typeof cat.name === 'object' && cat.name.tr) {
        console.log(`Skipping already migrated category: ${cat._id}`)
        continue
      }
      
      const update = {
        name: {
          tr: cat.name || 'İsimsiz',
          en: translateCategoryName(cat.name) || cat.name || 'Unnamed'
        },
        description: {
          tr: cat.description || '',
          en: cat.description || ''
        }
      }
      
      await db.collection('categories').updateOne(
        { _id: cat._id },
        { $set: update }
      )
      console.log(`Migrated category: ${cat.name}`)
    }
    
    console.log('Migration completed successfully!')
    process.exit(0)
  } catch (error) {
    console.error('Migration failed:', error)
    process.exit(1)
  }
}

// Simple translation map for common category names
function translateCategoryName(trName) {
  const translations = {
    'Directory Bruteforce': 'Directory Bruteforce',
    'Exploitation': 'Exploitation',
    'Network Scanning': 'Network Scanning',
    'Network Utilities': 'Network Utilities',
    'Password Cracking': 'Password Cracking',
    'SQL Injection': 'SQL Injection',
    'Subdomain Discovery': 'Subdomain Discovery',
    'Web Enumeration': 'Web Enumeration',
    'Wireless': 'Wireless'
  }
  return translations[trName] || trName
}

migrate()
