const fs = require('fs');

const data = JSON.parse(fs.readFileSync('./mdb/cheatsheets.json', 'utf8'));

console.log('=== CHEATSHEET DATA ANALYSIS ===\n');
console.log(`Total cheatsheets: ${data.length}\n`);

let issues = {
  missingTitle: [],
  missingDesc: [],
  noTags: [],
  noLinks: [],
  emptyDesc: []
};

data.forEach((sheet, idx) => {
  if (!sheet.title) issues.missingTitle.push(idx);
  if (!sheet.description) issues.missingDesc.push(sheet.title || `#${idx}`);
  if (!sheet.tags || sheet.tags.length === 0) issues.noTags.push(sheet.title);
  if (!sheet.links || sheet.links.length === 0) issues.noLinks.push(sheet.title);
  if (sheet.description && sheet.description.length < 100) issues.emptyDesc.push(sheet.title);
});

console.log('=== DATA QUALITY ISSUES ===');
console.log(`Missing titles: ${issues.missingTitle.length}`);
console.log(`Missing descriptions: ${issues.missingDesc.length}`);
if (issues.missingDesc.length > 0) console.log(`  - ${issues.missingDesc.slice(0,3).join(', ')}`);
console.log(`No tags: ${issues.noTags.length}`);
if (issues.noTags.length > 0) console.log(`  - ${issues.noTags.slice(0,3).join(', ')}`);
console.log(`No links: ${issues.noLinks.length}`);
if (issues.noLinks.length > 0) console.log(`  - ${issues.noLinks.slice(0,3).join(', ')}`);
console.log(`Short descriptions (<100 chars): ${issues.emptyDesc.length}`);
if (issues.emptyDesc.length > 0) console.log(`  - ${issues.emptyDesc.slice(0,3).join(', ')}`);

console.log('\n=== SAMPLE CHEATSHEETS (First 5) ===');
data.slice(0, 5).forEach((sheet, idx) => {
  console.log(`\n${idx+1}. ${sheet.title}`);
  console.log(`   Tags: ${sheet.tags?.join(', ') || 'NONE'}`);
  console.log(`   Links: ${sheet.links?.length || 0} link(s)`);
  console.log(`   Description: ${sheet.description?.length || 0} chars`);
  console.log(`   Category ID: ${sheet.category?.$oid || 'MISSING'}`);
});

console.log('\n\n=== SUMMARY ===');
console.log(`✓ All cheatsheets have titles: ${issues.missingTitle.length === 0 ? 'YES' : 'NO'}`);
console.log(`✓ All have descriptions: ${issues.missingDesc.length === 0 ? 'YES' : 'NO'}`);
console.log(`✓ All have tags: ${issues.noTags.length === 0 ? 'YES' : 'NO'}`);
console.log(`✓ All have links: ${issues.noLinks.length === 0 ? 'YES' : 'NO'}`);
console.log(`✓ Average description length: ${Math.round(data.reduce((sum, s) => sum + (s.description?.length || 0), 0) / data.length)} chars`);
