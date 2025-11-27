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
        await dbConnect();
        console.log('Connected to DB. Migrating categories...');

        const categories = await Category.find({});
        console.log(`Found ${categories.length} categories.`);

        let updated = 0;
        for (const cat of categories) {
            // Use ._doc to access raw data if needed, or just check type
            const rawName = cat.get('name');
            const rawDesc = cat.get('description');

            let modified = false;
            const update = {};

            if (typeof rawName === 'string') {
                console.log(`Migrating name for: ${rawName}`);
                update.name = { tr: rawName, en: rawName };
                modified = true;
            }

            if (typeof rawDesc === 'string') {
                update.description = { tr: rawDesc, en: rawDesc };
                modified = true;
            }

            if (modified) {
                // Use updateOne to bypass some mongoose weirdness if save() fails
                await Category.updateOne({ _id: cat._id }, { $set: update });
                updated++;
            }
        }

        console.log(`Migrated ${updated} categories.`);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

migrate();
