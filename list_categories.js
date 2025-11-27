import dbConnect from './lib/dbConnect.js';
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

async function listCategories() {
    try {
        await dbConnect();
        console.log('Connected to DB. Listing categories...');

        const categories = await Category.find({}).lean();
        console.log(`Total categories: ${categories.length}`);

        categories.forEach(c => {
            console.log(`- ID: ${c._id}`);
            console.log(`  Name: ${JSON.stringify(c.name)}`);
            console.log(`  Slug: ${c.slug} (Expected: undefined if not in schema)`);
            console.log(`  Icon: ${c.icon} (Expected: undefined if not in schema)`);
        });

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

listCategories();
