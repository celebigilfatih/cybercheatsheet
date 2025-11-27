import dbConnect from '../lib/dbConnect.js';
import Category from '../models/Category.js';
import mongoose from 'mongoose';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load .env.local
const envPath = path.join(__dirname, '..', '.env.local');
if (fs.existsSync(envPath)) {
    const lines = fs.readFileSync(envPath, 'utf-8').split(/\r?\n/);
    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const idx = trimmed.indexOf('=');
        if (idx === -1) continue;
        const key = trimmed.slice(0, idx).trim();
        const val = trimmed.slice(idx + 1).trim();
        if (key && !(key in process.env)) process.env[key] = val;
    }
}

async function migrate() {
    try {
        console.log('Connecting to DB...');
        await dbConnect();
        console.log('Connected.');

        // Use lean() to get raw data
        const categories = await Category.find({}).lean();
        console.log(`Found ${categories.length} categories.`);

        let updated = 0;
        for (const cat of categories) {
            let needsUpdate = false;
            const updates = {};

            // Check name
            if (typeof cat.name === 'string') {
                console.log(`Migrating name for category: ${cat.name}`);
                updates.name = { tr: cat.name, en: cat.name };
                needsUpdate = true;
            }

            // Check description
            if (typeof cat.description === 'string') {
                updates.description = { tr: cat.description, en: cat.description };
                needsUpdate = true;
            }

            if (needsUpdate) {
                await Category.updateOne({ _id: cat._id }, { $set: updates });
                updated++;
            }
        }

        console.log(`Migration completed. Updated ${updated} categories.`);

    } catch (error) {
        console.error('Migration failed:', error);
    } finally {
        await mongoose.disconnect();
    }
}

migrate();
