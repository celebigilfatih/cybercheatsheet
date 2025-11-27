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

async function checkHashcat() {
    try {
        await dbConnect();
        const sheet = await Cheatsheet.findOne({ 'title.tr': /hashcat/i }).lean();

        if (sheet) {
            console.log('TR Length:', sheet.description.tr.length);
            console.log('EN Length:', sheet.description.en.length);
            if (sheet.description.tr !== sheet.description.en) {
                console.log('SUCCESS: Content differs.');
            } else {
                console.log('FAIL: Content is identical.');
            }
        } else {
            console.log('Hashcat Cheatsheet NOT FOUND');
        }

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

checkHashcat();
