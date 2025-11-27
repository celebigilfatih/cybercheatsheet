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

async function reproduce() {
    try {
        await dbConnect();
        console.log('Connected to DB.');

        // Simulate API logic
        const filter = {};
        const cheatsheets = await Cheatsheet.find(filter)
            .populate('category')
            .sort({ updatedAt: -1 })
            .lean();

        console.log(`Found ${cheatsheets.length} cheatsheets.`);

        if (cheatsheets.length > 0) {
            const first = cheatsheets[0];
            console.log('First cheatsheet:', JSON.stringify(first, null, 2));

            // Check if title is object
            console.log('Title type:', typeof first.title);
            console.log('Title is object?', typeof first.title === 'object');

            // Check category
            console.log('Category populated?', !!first.category);
            if (first.category) {
                console.log('Category name:', first.category.name);
            }
        } else {
            console.log('No cheatsheets found!');
        }

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

reproduce();
