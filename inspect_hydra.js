import dbConnect from './lib/dbConnect.js';
import Cheatsheet from './models/Cheatsheet.js';
import Category from './models/Category.js';
import mongoose from 'mongoose';

async function inspectHydra() {
    try {
        await dbConnect();
        const cs = await Cheatsheet.findOne({ 'title.en': 'Hydra Cheat Sheet' }).populate('category');
        if (!cs) {
            console.log('Hydra not found');
            return;
        }
        console.log('Found Hydra Cheatsheet:');
        console.log('Category:', cs.category.name.en);
        console.log('TR Length:', cs.description.tr.length);
        console.log('EN Length:', cs.description.en.length);

        console.log('\n--- TR Snippet ---');
        console.log(cs.description.tr.substring(0, 100));
        console.log('\n--- EN Snippet ---');
        console.log(cs.description.en.substring(0, 100));

    } catch (error) {
        console.error(error);
    } finally {
        await mongoose.disconnect();
    }
}

inspectHydra();
