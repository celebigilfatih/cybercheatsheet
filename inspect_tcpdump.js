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

async function inspectTcpdump() {
    try {
        await dbConnect();
        const sheet = await Cheatsheet.findOne({
            $or: [
                { 'title.en': /tcpdump/i },
                { 'title.tr': /tcpdump/i }
            ]
        }).lean();

        if (sheet) {
            console.log('Found Tcpdump Cheatsheet:');
            const tr = sheet.description.tr || '';
            const en = sheet.description.en || '';

            console.log('TR Length:', tr.length);
            console.log('EN Length:', en.length);

            if (tr === en) {
                console.log('WARNING: TR and EN content are IDENTICAL!');
                console.log('Content Start:', tr.substring(0, 100));
            } else {
                console.log('Content differs.');
            }

            // Print full TR content for translation reference
            console.log('\n--- FULL TR CONTENT ---\n');
            console.log(tr);
            console.log('\n--- END TR CONTENT ---\n');

        } else {
            console.log('Tcpdump Cheatsheet NOT FOUND');
        }

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

inspectTcpdump();
