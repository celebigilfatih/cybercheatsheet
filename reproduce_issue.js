import dbConnect from './lib/dbConnect.js';
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

async function run() {
    try {
        console.log('Connecting to DB...');
        await dbConnect();
        console.log('Connected.');

        console.log('Fetching categories (Mongoose Documents)...');
        const categories = await Category.find({}).sort({ name: 1 });
        console.log(`Found ${categories.length} categories.`);
        if (categories.length > 0) {
            console.log('First category name type:', typeof categories[0].name);
            console.log('First category name value:', categories[0].name);
            console.log('First category name.tr:', categories[0].name?.tr);
        }

        console.log('Fetching categories (lean)...');
        const leanCategories = await Category.find({}).sort({ name: 1 }).lean();
        console.log(`Found ${leanCategories.length} lean categories.`);
        if (leanCategories.length > 0) {
            console.log('First lean category name type:', typeof leanCategories[0].name);
            console.log('First lean category name value:', leanCategories[0].name);
        }

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

run();
