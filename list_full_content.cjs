const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function listFullContentSheets() {
  try {
    const sheets = await prisma.cheatsheet.findMany({
      select: {
        id: true,
        titleEn: true,
        titleTr: true,
        descEn: true,
        descTr: true,
        tags: true,
        category: {
          select: {
            nameEn: true
          }
        }
      }
    });

    console.log('--- CHEATSHEETS WITH SUBSTANTIAL CONTENT ---');
    
    // Sort by combined content length descending
    const substantialSheets = sheets
      .map(s => ({
        id: s.id,
        title: s.titleEn || s.titleTr,
        enLen: (s.descEn || '').length,
        trLen: (s.descTr || '').length,
        totalLen: (s.descEn || '').length + (s.descTr || '').length,
        category: s.category?.nameEn || 'N/A',
        tags: s.tags
      }))
      .filter(s => s.totalLen > 100) // Consider "full" if more than 100 chars total
      .sort((a, b) => b.totalLen - a.totalLen);

    substantialSheets.forEach((s, i) => {
      console.log(`${i + 1}. [ID: ${s.id}] ${s.title}`);
      console.log(`   Category: ${s.category}`);
      console.log(`   Content Length: EN: ${s.enLen} chars | TR: ${s.trLen} chars`);
      console.log(`   Tags: ${s.tags.join(', ')}`);
      console.log('-------------------------------------------');
    });

    console.log(`Total "full" documents found: ${substantialSheets.length}`);
  } catch (err) {
    console.error('Error fetching sheets:', err.message);
  } finally {
    await prisma.$disconnect();
  }
}

listFullContentSheets();
