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

async function testApiHandler() {
    try {
        console.log('Connecting to DB...');
        await dbConnect();
        console.log('Connected.');

        console.log('Running query: Category.find({}).sort({ name: 1 })');
        try {
            const categories = await Category.find({}).sort({ name: 1 });
            console.log(`Query successful. Found ${categories.length} categories.`);
            console.log('First category:', JSON.stringify(categories[0], null, 2));
        } catch (err) {
            console.error('Query failed:', err);
        }

        console.log('Running query: Category.find({}).sort({ "name.tr": 1 }).lean()');
        try {
            const categoriesLean = await Category.find({}).sort({ "name.tr": 1 }).lean();
            console.log(`Lean query successful. Found ${categoriesLean.length} categories.`);
            console.log('First lean category:', JSON.stringify(categoriesLean[0], null, 2));
        } catch (err) {
            console.error('Lean query failed:', err);
        }

    } catch (error) {
        console.error('General error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

testApiHandler();
