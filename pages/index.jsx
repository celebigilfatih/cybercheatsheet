import { useEffect, useState } from 'react'
import Sidebar from '../components/Sidebar'
import CheatsheetCard from '../components/CheatsheetCard'
import { useLanguage } from '../lib/LanguageContext'
import { HiOutlineSearch, HiOutlineFilter, HiOutlineRefresh } from 'react-icons/hi'

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

  useEffect(() => {
    load()
  }, [])

  const exportMD = (sheet) => {
    const content = language === 'en' 
      ? (sheet.descEn || sheet.description?.[language] || sheet.description?.tr || sheet.description || '')
      : (sheet.descTr || sheet.description?.[language] || sheet.description?.tr || sheet.description || '')
    const blob = new Blob([content], { type: 'text/markdown;charset=utf-8' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    const title = sheet.titleEn || sheet.title?.[language] || sheet.title?.tr || sheet.title || 'cheatsheet'
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
    const content = language === 'en' 
      ? (sheet.descEn || sheet.description?.[language] || sheet.description?.tr || sheet.description || '')
      : (sheet.descTr || sheet.description?.[language] || sheet.description?.tr || sheet.description || '')
    temp.innerText = content
    document.body.appendChild(temp)
    const canvas = await html2canvas(temp)
    const imgData = canvas.toDataURL('image/png')
    const pdf = new jsPDF('p', 'mm', 'a4')
    const pageWidth = pdf.internal.pageSize.getWidth()
    const pageHeight = pdf.internal.pageSize.getHeight()
    pdf.addImage(imgData, 'PNG', 0, 0, pageWidth, pageHeight)
    const title = sheet.titleEn || sheet.title?.[language] || sheet.title?.tr || sheet.title || 'cheatsheet'
    pdf.save(`${title.replace(/\s+/g, '-')}.pdf`)
    document.body.removeChild(temp)
  }

  return (
    <main className="h-full flex">
      <Sidebar onSelectCategory={setCategory} activeCategory={category} />
      
      <section className="flex-1 flex flex-col min-h-0 overflow-hidden">
        {/* Search Bar */}
        <div className="flex-shrink-0 px-4 py-3 border-b border-gray-800/60 bg-cyber-panel/30">
          <div className="flex items-center gap-2">
            {/* Search Input */}
            <div className="flex-1 relative">
              <HiOutlineSearch className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
              <input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder={t('search.placeholder')}
                className="w-full pl-8 pr-3 py-1.5 text-sm rounded-md bg-gray-900/80 border border-gray-800 focus:border-cyber-accent/50 focus:outline-none transition-colors"
              />
            </div>
            
            {/* Tag Filter */}
            <div className="w-40 relative">
              <HiOutlineFilter className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
              <input
                value={tag}
                onChange={(e) => setTag(e.target.value)}
                placeholder={t('search.filterByTag')}
                className="w-full pl-8 pr-3 py-1.5 text-sm rounded-md bg-gray-900/80 border border-gray-800 focus:border-cyber-accent/50 focus:outline-none transition-colors"
              />
            </div>
            
            {/* Search Button */}
            <button 
              onClick={load} 
              className="flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium bg-cyber-accent text-black rounded-md hover:bg-cyber-accent/80 transition-colors"
            >
              <HiOutlineRefresh className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
              {t('search.button')}
            </button>
          </div>
        </div>

        {/* Results Grid */}
        <div className="flex-1 overflow-y-auto p-4">
          {loading && (
            <div className="flex items-center justify-center py-8">
              <div className="flex items-center gap-2 text-gray-400">
                <HiOutlineRefresh className="w-5 h-5 animate-spin" />
                <span>{t('search.loading')}</span>
              </div>
            </div>
          )}
          
          {!loading && sheets.length === 0 && (
            <div className="flex items-center justify-center py-8 text-gray-500">
              {t('search.noResults')}
            </div>
          )}
          
          {!loading && sheets.length > 0 && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-3 2xl:grid-cols-3 gap-6">
              {sheets.map((s) => (
                <CheatsheetCard 
                  key={s.id || s._id} 
                  sheet={s} 
                  onExportMD={exportMD} 
                  onExportPDF={exportPDF} 
                />
              ))}
            </div>
          )}
        </div>

        {/* Footer Stats */}
        {!loading && sheets.length > 0 && (
          <div className="flex-shrink-0 px-4 py-2 border-t border-gray-800/60 bg-cyber-panel/30">
            <span className="text-xs text-gray-500">
              {sheets.length} {sheets.length === 1 ? 'document' : 'documents'}
            </span>
          </div>
        )}
      </section>
    </main>
  )
}
