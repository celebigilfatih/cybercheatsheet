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

async function checkWebEnum() {
    try {
        await dbConnect();

        const webEnum = await Category.findOne({ 'name.en': 'Web Enumeration' });
        const webSec = await Category.findOne({ 'name.en': 'Web Application Security' });

        if (webEnum) {
            const count = await Cheatsheet.countDocuments({ category: webEnum._id });
            console.log(`"Web Enumeration" has ${count} cheatsheets.`);
        }

        if (webSec) {
            const count = await Cheatsheet.countDocuments({ category: webSec._id });
            console.log(`"Web Application Security" has ${count} cheatsheets.`);
        }

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

checkWebEnum();
