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

async function listAll() {
    try {
        await dbConnect();

        console.log('--- Categories ---');
        const categories = await Category.find({}).lean();
        categories.forEach(c => {
            console.log(`ID: ${c._id}, Name: ${JSON.stringify(c.name)}`);
        });

        console.log('\n--- Cheatsheets ---');
        const sheets = await Cheatsheet.find({}).lean();
        sheets.forEach(s => {
            console.log(`ID: ${s._id}, Title: ${JSON.stringify(s.title)}, Category: ${s.category}`);
        });

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

listAll();
