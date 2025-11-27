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

async function cleanup() {
    try {
        await dbConnect();
        console.log('Connected to DB. Cleaning up...');

        // 1. Delete "Wireless" (Empty)
        const wireless = await Category.findOne({ 'name.en': 'Wireless' });
        if (wireless) {
            const count = await Cheatsheet.countDocuments({ category: wireless._id });
            if (count === 0) {
                console.log('Deleting empty category "Wireless"...');
                await Category.findByIdAndDelete(wireless._id);
                console.log('Deleted.');
            } else {
                console.log('"Wireless" is not empty, skipping.');
            }
        }

        // 2. Move SQLMap from "SQL Injection" to "Database Exploitation"
        const sqlInj = await Category.findOne({ 'name.en': 'SQL Injection' });
        const dbExploit = await Category.findOne({ 'name.en': 'Database Exploitation' });

        if (sqlInj && dbExploit) {
            console.log('Moving cheatsheets from "SQL Injection" to "Database Exploitation"...');
            const res = await Cheatsheet.updateMany(
                { category: sqlInj._id },
                { category: dbExploit._id }
            );
            console.log(`Moved ${res.modifiedCount} cheatsheets.`);

            console.log('Deleting category "SQL Injection"...');
            await Category.findByIdAndDelete(sqlInj._id);
            console.log('Deleted.');
        }

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

cleanup();
