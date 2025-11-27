import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const cheatsheetsPath = path.join(__dirname, '..', 'mdb', 'cheatsheets.json');

try {
    const data = JSON.parse(fs.readFileSync(cheatsheetsPath, 'utf-8'));
    let updatedCount = 0;

    const updatedData = data.map(sheet => {
        let modified = false;
        const newSheet = { ...sheet };

        // Convert title
        if (typeof newSheet.title === 'string') {
            newSheet.title = { tr: newSheet.title, en: newSheet.title };
            modified = true;
        }

        // Convert description
        if (typeof newSheet.description === 'string') {
            newSheet.description = { tr: newSheet.description, en: newSheet.description };
            modified = true;
        }

        if (modified) updatedCount++;
        return newSheet;
    });

    fs.writeFileSync(cheatsheetsPath, JSON.stringify(updatedData, null, 2));
    console.log(`Fixed ${updatedCount} cheatsheets in JSON file.`);

} catch (err) {
    console.error('Error fixing JSON:', err);
}
