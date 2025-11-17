# CyberSec Cheatsheet

A secure, clean, and modern web app to organize cybersecurity documentation, command cheatsheets, and external links.

## Tech Stack

- Frontend: Next.js + Tailwind CSS
- Backend: Next.js API Routes (Node.js)
- Database: MongoDB (Mongoose)
- Authentication: Optional JWT (single user via env)

## Environment Variables

Create a `.env.local` file with:

```
MONGODB_URI=mongodb+srv://<user>:<pass>@<cluster>/<db>?retryWrites=true&w=majority
JWT_SECRET=change-me
# Optional single-user auth (enables auth enforcement)
ADMIN_USER=admin
ADMIN_PASS=yourStrongPassword
```

## Run Locally

```
npm install
npm run dev
```

Visit http://localhost:3000

## Project Structure

```
/models
  Category.js
  Cheatsheet.js

/lib
  dbConnect.js
  auth.js

/pages
  _app.jsx
  index.jsx
  new.jsx
  /category/[id].jsx
  /cheatsheet/[id].jsx

/pages/api
  /categories/index.js, [id].js
  /cheatsheets/index.js, [id].js
  /auth/login.js

/components
  Sidebar.jsx
  CheatsheetCard.jsx
  MarkdownEditor.jsx
```

## Security

- Security headers via Next.js `headers()` configured in `next.config.js`.
- Markdown sanitized on both client (DOMPurify) and server (sanitize-html).
- Optional JWT auth to restrict write operations.
- Tailwind Typography for markdown rendering.

## Notes

- Add your initial categories via `/api/categories` POST if auth disabled, or login to retrieve JWT and pass `Authorization: Bearer <token>` when enabled.
- Search supports full-text (`q`), category filter (`category`), and tag filter (`tag`).
# CyberSec Cheatsheet
## Seeding (Veri Doldurma)

Uygulamayı örnek kategoriler ve popüler araç cheatsheet’leri ile doldurmak için iki seçenek vardır:

- HTTP Seed API (SEED_SECRET gerektirir):
  - `.env.local` içine `MONGODB_URI` ve `SEED_SECRET` ekleyin.
  - Dev sunucuyu çalıştırın: `npm run dev`.
  - Çalıştırın: `curl -X POST http://localhost:3000/api/seed -H "Content-Type: application/json" -d '{"secret":"<SEED_SECRET>"}'`.

- CLI Seed Script (ENV ile çalışır):
  - `.env.local` içine `MONGODB_URI` (ve opsiyonel `JWT_SECRET`) ekleyin.
  - Komut: `npm run seed`.

İçerikler: Nmap, Masscan, Gobuster, FFUF, Dirsearch, Nikto, SQLMap, Hydra, Netcat, Tcpdump, Amass, John, Hashcat, Metasploit, WPScan, Wfuzz, Sublist3r, TShark, Aircrack-ng, Ncrack.

Not: Seed işlemi “upsert” yapar; mevcut kayıtları günceller, yoksa ekler.

### JSON Dataset ile Genişletme

Tam veya genişletilmiş Kali araç listesini JSON ile içe aktarabilirsiniz:

- Dosya yolu: `data/kali-tools.json`
- Şema:

```
{
  "categories": [ { "name": "Network Scanning", "description": "..." }, ... ],
  "sheets": [
    {
      "title": "Nmap Cheatsheet",
      "category": "Network Scanning",
      "tags": ["nmap","scan"],
      "links": ["https://nmap.org/"],
      "description": "# Nmap..."
    },
    ...
  ]
}
```

Seed çalıştırıldığında `data/kali-tools.json` varsa otomatik olarak öncelik verir (API ve CLI). Böylece resmi Kali araç listesini veya kendi düzenlediğiniz veri setini topluca içe aktarabilirsiniz.