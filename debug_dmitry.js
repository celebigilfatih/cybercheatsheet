import dbConnect from './lib/dbConnect.js';
import Cheatsheet from './models/Cheatsheet.js';
import Category from './models/Category.js';
import mongoose from 'mongoose';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load .env.local
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

async function debug() {
    try {
        await dbConnect();

        // 1. Find the category "Web Enumeration"
        // Note: It might be stored as { tr: ..., en: ... } now
        const category = await Category.findOne({
            $or: [
                { name: 'Web Enumeration' },
                { 'name.en': 'Web Enumeration' },
                { 'name.tr': 'Web Enumeration' }
            ]
        }).lean();

        if (!category) {
            console.error('Category "Web Enumeration" NOT FOUND in DB!');
        } else {
            console.log('Category "Web Enumeration" found:');
            console.log('  _id:', category._id.toString());
            console.log('  name:', category.name);
        }

        // 2. Find the DMitry cheatsheet
        const sheet = await Cheatsheet.findOne({ 'title.en': 'DMitry Cheatsheet' }).lean();

        if (!sheet) {
            console.error('DMitry Cheatsheet NOT FOUND in DB!');
        } else {
            console.log('DMitry Cheatsheet found:');
            console.log('  _id:', sheet._id.toString());
            console.log('  category (in sheet):', sheet.category.toString());

            if (category && sheet.category.toString() !== category._id.toString()) {
                console.error('MISMATCH: Cheatsheet category ID does not match actual Category ID!');

                // Fix it
                console.log('Fixing mismatch...');
                await Cheatsheet.updateOne(
                    { _id: sheet._id },
                    { $set: { category: category._id } }
                );
                console.log('Fixed. Updated cheatsheet category to:', category._id.toString());
            } else if (category) {
                console.log('MATCH: IDs match correctly.');
            }
        }

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

debug();
