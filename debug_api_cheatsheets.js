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

async function simulateApi() {
    try {
        await dbConnect();

        console.log('Simulating GET /api/cheatsheets...');
        const filter = {};
        // Simulate what the API does
        const cheatsheets = await Cheatsheet.find(filter)
            .populate('category')
            .sort({ updatedAt: -1 })
            .lean();

        console.log(`API returned ${cheatsheets.length} cheatsheets.`);

        if (cheatsheets.length > 0) {
            console.log('Sample (first 3):');
            cheatsheets.slice(0, 3).forEach(s => {
                console.log(`- Title: ${JSON.stringify(s.title)}, Category: ${s.category ? s.category.name.en : 'NULL'}`);
            });
        }

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

simulateApi();
