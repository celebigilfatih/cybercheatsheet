import dbConnect from './lib/dbConnect.js';
import Cheatsheet from './models/Cheatsheet.js';
import Category from './models/Category.js'; // Import Category to register schema
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

async function check() {
    try {
        // Check JSON file
        const jsonPath = path.join(__dirname, 'mdb', 'cheatsheets.json');
        if (fs.existsSync(jsonPath)) {
            const jsonData = JSON.parse(fs.readFileSync(jsonPath, 'utf-8'));
            console.log(`JSON File Count: ${jsonData.length}`);
        } else {
            console.log('JSON File NOT FOUND');
        }

        // Check DB
        await dbConnect();
        const count = await Cheatsheet.countDocuments({});
        console.log(`DB Document Count: ${count}`);

        const all = await Cheatsheet.find({}).populate('category').lean();
        all.forEach(s => {
            const title = s.title ? (s.title.en || s.title.tr || s.title) : 'NO_TITLE';
            const catName = s.category ? (s.category.name.en || s.category.name.tr || s.category.name) : 'NULL';
            console.log(`- [${s._id}] ${title} (Cat: ${catName})`);
        });

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

check();
