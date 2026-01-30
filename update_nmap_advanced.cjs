const fs = require('fs');
const content = fs.readFileSync('nmap_guide_advanced.md', 'utf8');

async function updateNmap() {
  try {
    // Login
    const loginRes = await fetch('http://localhost:3311/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'admin123' })
    });
    const auth = await loginRes.json();
    
    if (!auth.token) {
      console.log('Login failed:', auth.error);
      return;
    }
    console.log('Login successful');
    
    // Update Nmap with advanced content
    const updateRes = await fetch('http://localhost:3311/api/cheatsheets/740', {
      method: 'PUT',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + auth.token
      },
      body: JSON.stringify({
        titleEn: 'Nmap Mastery - Complete Guide',
        titleTr: 'Nmap Uzmanlık Rehberi',
        descriptionEn: content,
        descriptionTr: content,
        categoryId: 235
      })
    });
    
    const result = await updateRes.json();
    if (result.cheatsheet) {
      console.log('✓ Nmap updated successfully!');
      console.log('✓ Content length:', content.length, 'characters');
      console.log('✓ Sections: Beginner → Intermediate → Advanced → Expert → Elite');
    } else {
      console.log('✗ Update failed:', result.error);
    }
  } catch (e) {
    console.error('Error:', e.message);
  }
}

updateNmap();
