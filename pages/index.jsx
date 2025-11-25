import { useEffect, useState } from 'react'
import Sidebar from '../components/Sidebar'
import CheatsheetCard from '../components/CheatsheetCard'
import { useLanguage } from '../lib/LanguageContext'

export default function Home() {
  const [category, setCategory] = useState(null)
  const [q, setQ] = useState('')
  const [tag, setTag] = useState('')
  const [sheets, setSheets] = useState([])
  const [loading, setLoading] = useState(false)
  const { t, language } = useLanguage()

  const load = async () => {
    setLoading(true)
    const params = new URLSearchParams()
    if (q) params.set('q', q)
    if (category) params.set('category', category)
    if (tag) params.set('tag', tag)
    const res = await fetch(`/api/cheatsheets?${params.toString()}`)
    const data = await res.json()
    setSheets(data.cheatsheets || [])
    setLoading(false)
  }

  useEffect(() => {
    load()
  }, [category])

  const exportMD = (sheet) => {
    const content = sheet.description?.[language] || sheet.description?.tr || sheet.description || ''
    const blob = new Blob([content], { type: 'text/markdown;charset=utf-8' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    const title = sheet.title?.[language] || sheet.title?.tr || sheet.title || 'cheatsheet'
    a.download = `${title.replace(/\s+/g, '-')}.md`
    a.click()
  }

  const exportPDF = async (sheet) => {
    const { jsPDF } = await import('jspdf')
    const { default: html2canvas } = await import('html2canvas')
    const temp = document.createElement('div')
    temp.className = 'prose prose-invert'
    temp.style.position = 'fixed'
    temp.style.left = '-9999px'
    const content = sheet.description?.[language] || sheet.description?.tr || sheet.description || ''
    temp.innerText = content
    document.body.appendChild(temp)
    const canvas = await html2canvas(temp)
    const imgData = canvas.toDataURL('image/png')
    const pdf = new jsPDF('p', 'mm', 'a4')
    const pageWidth = pdf.internal.pageSize.getWidth()
    const pageHeight = pdf.internal.pageSize.getHeight()
    pdf.addImage(imgData, 'PNG', 0, 0, pageWidth, pageHeight)
    const title = sheet.title?.[language] || sheet.title?.tr || sheet.title || 'cheatsheet'
    pdf.save(`${title.replace(/\s+/g, '-')}.pdf`)
    document.body.removeChild(temp)
  }

  return (
    <main className="mx-auto max-w-7xl grid grid-cols-[16rem_1fr] gap-0">
      <Sidebar onSelectCategory={setCategory} activeCategory={category} />
      <section className="p-6">
        <div className="panel p-4 mb-4">
          <div className="grid md:grid-cols-4 gap-3">
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder={t('search.placeholder')}
              className="px-3 py-2 rounded bg-gray-900 border border-gray-800"
            />
            <input
              value={tag}
              onChange={(e) => setTag(e.target.value)}
              placeholder={t('search.filterByTag')}
              className="px-3 py-2 rounded bg-gray-900 border border-gray-800"
            />
            <button onClick={load} className="btn-primary">{t('search.button')}</button>
            <a href="/new" className="btn-secondary text-center">{t('search.newCheatsheet')}</a>
          </div>
        </div>

        {loading && <div className="text-gray-400">{t('search.loading')}</div>}
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
          {sheets.map((s) => (
            <CheatsheetCard key={s._id} sheet={s} onExportMD={exportMD} onExportPDF={exportPDF} />
          ))}
          {sheets.length === 0 && !loading && (
            <div className="text-gray-400">{t('search.noResults')}</div>
          )}
        </div>
      </section>
    </main>
  )
}