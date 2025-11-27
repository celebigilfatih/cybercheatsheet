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

async function checkWafw00f() {
    try {
        await dbConnect();
        const cs = await Cheatsheet.findOne({ 'title.en': 'WAFW00F Cheat Sheet' }).populate('category');
        if (!cs) {
            console.log('WAFW00F not found');
            return;
        }
        console.log('WAFW00F Category:', cs.category.name);
        console.log('WAFW00F Category ID:', cs.category._id);

    } catch (error) {
        console.error(error);
    } finally {
        await mongoose.disconnect();
    }
}

checkWafw00f();
