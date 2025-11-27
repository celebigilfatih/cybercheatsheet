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

async function inspectDirb() {
    try {
        await dbConnect();
        // Search for Dirb case-insensitive
        const sheet = await Cheatsheet.findOne({
            $or: [
                { 'title.en': /dirb/i },
                { 'title.tr': /dirb/i },
                { 'title': /dirb/i }
            ]
        }).lean();

        if (sheet) {
            console.log('Found Dirb Cheatsheet:');
            console.log('Title Type:', typeof sheet.title);
            console.log('Title:', JSON.stringify(sheet.title, null, 2));
            console.log('Description Type:', typeof sheet.description);
            console.log('Description (first 100 chars):', JSON.stringify(sheet.description).substring(0, 100));

            if (typeof sheet.description === 'object') {
                console.log('Description Keys:', Object.keys(sheet.description));
            }
        } else {
            console.log('Dirb Cheatsheet NOT FOUND');
        }

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

inspectDirb();
