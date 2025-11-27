import dbConnect from '../lib/dbConnect.js';
import Cheatsheet from '../models/Cheatsheet.js';
import Category from '../models/Category.js';
import mongoose from 'mongoose';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const envPath = path.join(__dirname, '..', '.env.local');
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

async function updateNetcat() {
    try {
        await dbConnect();
        console.log('DB bağlantısı kuruldu. Netcat güncelleniyor...');

        let category = await Category.findOne({ 'name.en': 'Post Exploitation' });
        if (!category) {
            category = await Category.create({
                name: { tr: 'Post Exploitation', en: 'Post Exploitation' },
                description: { tr: 'Sistem ele geçirme sonrası araçlar', en: 'Post-compromise tools' },
                slug: 'post-exploitation',
                icon: 'Terminal'
            });
        }

        const contentTR = fs.readFileSync(path.join(__dirname, 'netcat_tr.txt'), 'utf-8');
        const contentEN = fs.readFileSync(path.join(__dirname, 'netcat_en.txt'), 'utf-8');

        const result = await Cheatsheet.findOneAndUpdate(
            { 'title.en': 'Netcat Cheat Sheet' },
            {
                title: { tr: 'Netcat Cheat Sheet', en: 'Netcat Cheat Sheet' },
                description: { tr: contentTR, en: contentEN },
                category: category._id,
                tags: ['netcat', 'nc', 'ncat', 'reverse-shell', 'bind-shell', 'pivoting', 'file-transfer']
            },
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        console.log('Netcat güncellendi:', result.title);
    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

updateNetcat();
