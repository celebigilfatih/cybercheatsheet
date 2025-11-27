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

async function checkContents() {
    try {
        await dbConnect();

        const catsToCheck = ['SQL Injection', 'Exploitation', 'Wireless'];

        for (const name of catsToCheck) {
            const cat = await Category.findOne({ 'name.en': name });
            if (cat) {
                console.log(`--- Category: ${name} ---`);
                const sheets = await Cheatsheet.find({ category: cat._id }).lean();
                if (sheets.length === 0) {
                    console.log('  (Empty)');
                } else {
                    sheets.forEach(s => console.log(`  - ${s.title.en || s.title}`));
                }
            } else {
                console.log(`Category "${name}" not found.`);
            }
        }

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

checkContents();
