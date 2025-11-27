import dbConnect from './lib/dbConnect.js';
import Cheatsheet from './models/Cheatsheet.js';
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

async function verify() {
    try {
        await dbConnect();
        const sheet = await Cheatsheet.findOne({ 'title.tr': 'DMitry Cheatsheet' }).lean();
        if (sheet) {
            console.log('DMitry Cheatsheet found!');
            console.log('Title (TR):', sheet.title.tr);
            console.log('Title (EN):', sheet.title.en);
            console.log('Description length (TR):', sheet.description.tr.length);
            console.log('Description length (EN):', sheet.description.en.length);
        } else {
            console.log('DMitry Cheatsheet NOT found.');
        }
    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

verify();
