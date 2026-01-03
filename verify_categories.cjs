const fs = require('fs');

const cheatsheets = JSON.parse(fs.readFileSync('./mdb/cheatsheets.json', 'utf8'));
const categories = JSON.parse(fs.readFileSync('./mdb/categories.json', 'utf8'));

console.log('=== CATEGORY MAPPING VERIFICATION ===\n');

// Create category map
const categoryMap = {};
categories.forEach(cat => {
  categoryMap[cat._id.$oid] = cat.name.en;
});

console.log(`Total categories: ${categories.length}`);
console.log(`Total cheatsheets: ${cheatsheets.length}\n`);

// Check all mappings
let missingCategories = [];
let categoryUsage = {};

cheatsheets.forEach((sheet, idx) => {
  const catId = sheet.category.$oid;
  const catName = categoryMap[catId];
  
  if (!catName) {
    missingCategories.push({
      title: sheet.title,
      categoryId: catId,
      index: idx
    });
  } else {
    if (!categoryUsage[catName]) {
      categoryUsage[catName] = [];
    }
    categoryUsage[catName].push(sheet.title);
  }
});

console.log('=== CATEGORY USAGE ===');
Object.keys(categoryUsage).sort().forEach(cat => {
  console.log(`\n${cat}: ${categoryUsage[cat].length} cheatsheets`);
  console.log(`  - ${categoryUsage[cat].slice(0, 3).join(', ')}${categoryUsage[cat].length > 3 ? '...' : ''}`);
});

if (missingCategories.length > 0) {
  console.log('\n❌ ORPHANED CHEATSHEETS (no category found):');
  missingCategories.forEach(item => {
    console.log(`  - ${item.title} (ID: ${item.categoryId})`);
  });
} else {
  console.log('\n✅ All cheatsheets have valid category mappings!');
}

console.log('\n=== UNMAPPED CATEGORIES ===');
let unmappedCount = 0;
categories.forEach(cat => {
  const count = Object.values(categoryUsage).flat().filter(() => true).length;
  if (!Object.values(categoryUsage).flat().some(title => 
    cheatsheets.find(s => s.title === title && s.category.$oid === cat._id.$oid)
  )) {
    console.log(`  - ${cat.name.en} (${cat._id.$oid})`);
    unmappedCount++;
  }
});

if (unmappedCount === 0) {
  console.log('✅ All categories have at least one cheatsheet!');
} else {
  console.log(`⚠️  ${unmappedCount} empty categories found`);
}

console.log('\n=== SUMMARY ===');
console.log(`✓ Category verification: ${missingCategories.length === 0 ? 'PASS' : 'FAIL'}`);
console.log(`✓ All categories used: ${unmappedCount === 0 ? 'YES' : 'NO'}`);
