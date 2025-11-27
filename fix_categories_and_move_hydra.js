import dbConnect from './lib/dbConnect.js';
import Cheatsheet from './models/Cheatsheet.js';
import Category from './models/Category.js';
import mongoose from 'mongoose';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const envPath = path.join(__dirname, '.env.local');
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

async function fixCategories() {
    try {
        await dbConnect();
        console.log('Connected to DB. Fixing categories...');

        // 1. Find "Password Cracking" (Old/Duplicate) and "Password Attacks" (Target)
        // Note: Using regex to be safe or exact match
        const oldCat = await Category.findOne({ 'name.en': 'Password Cracking' });
        const targetCat = await Category.findOne({ 'name.en': 'Password Attacks' });

        if (oldCat && targetCat) {
            console.log(`Moving cheatsheets from "${oldCat.name.en}" to "${targetCat.name.en}"...`);
            const result = await Cheatsheet.updateMany(
                { category: oldCat._id },
                { category: targetCat._id }
            );
            console.log(`Moved ${result.modifiedCount} cheatsheets.`);

            console.log(`Deleting category "${oldCat.name.en}"...`);
            await Category.findByIdAndDelete(oldCat._id);
            console.log('Deleted.');
        } else {
            console.log('Categories for Password Cracking/Attacks not found or mismatch.');
            if (oldCat) console.log('Found Old:', oldCat.name);
            if (targetCat) console.log('Found Target:', targetCat.name);
        }

        // 2. Check for other duplicates if needed
        // For now, just fixing Hydra's category.

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

fixCategories();
