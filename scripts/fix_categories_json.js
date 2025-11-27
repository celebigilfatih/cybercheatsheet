import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const categoriesPath = path.join(__dirname, '..', 'mdb', 'categories.json');

try {
    const data = JSON.parse(fs.readFileSync(categoriesPath, 'utf-8'));
    let updatedCount = 0;

    const updatedData = data.map(cat => {
        let modified = false;
        const newCat = { ...cat };

        // Convert name
        if (typeof newCat.name === 'string') {
            newCat.name = { tr: newCat.name, en: newCat.name };
            modified = true;
        }

        // Convert description
        if (typeof newCat.description === 'string') {
            newCat.description = { tr: newCat.description, en: newCat.description };
            modified = true;
        }

        if (modified) updatedCount++;
        return newCat;
    });

    fs.writeFileSync(categoriesPath, JSON.stringify(updatedData, null, 2));
    console.log(`Fixed ${updatedCount} categories in JSON file.`);

} catch (err) {
    console.error('Error fixing categories JSON:', err);
}
