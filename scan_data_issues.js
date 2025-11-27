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

async function scanForIssues() {
    try {
        await dbConnect();
        console.log('Connected to DB. Scanning for data issues...');

        const cheatsheets = await Cheatsheet.find({})
            .populate('category')
            .lean();

        console.log(`Total cheatsheets: ${cheatsheets.length}`);
        let issues = 0;

        for (const cs of cheatsheets) {
            let hasIssue = false;
            const id = cs._id;
            const title = cs.title;

            // Check Title
            if (!title) {
                console.log(`[${id}] Missing title`);
                hasIssue = true;
            } else if (typeof title !== 'object') {
                console.log(`[${id}] Title is not object: ${typeof title} (${title})`);
                // This might be fine if frontend handles string, but we prefer object
            }

            // Check Category
            if (!cs.category) {
                console.log(`[${id}] Missing category (or failed populate)`);
                hasIssue = true;
            } else if (!cs.category.name) {
                console.log(`[${id}] Category has no name: ${cs.category._id}`);
                hasIssue = true;
            }

            if (hasIssue) issues++;
        }

        console.log(`Scan complete. Found ${issues} potential issues.`);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

scanForIssues();
