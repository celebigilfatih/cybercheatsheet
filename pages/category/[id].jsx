import { useEffect, useState } from 'react'
import CheatsheetCard from '../../components/CheatsheetCard'

export default function CategoryPage() {
  const [sheets, setSheets] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const id = window.location.pathname.split('/').pop()
    setLoading(true)
    fetch(`/api/cheatsheets?category=${id}`).then((r) => r.json()).then((d) => {
      setSheets(d.cheatsheets || [])
      setLoading(false)
    })
  }, [])

  const exportMD = (sheet) => {
    const blob = new Blob([sheet.description || ''], { type: 'text/markdown;charset=utf-8' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `${sheet.title.replace(/\s+/g, '-')}.md`
    a.click()
  }
  const exportPDF = async (sheet) => {
    const { jsPDF } = await import('jspdf')
    const { default: html2canvas } = await import('html2canvas')
    const temp = document.createElement('div')
    temp.className = 'prose prose-invert'
    temp.style.position = 'fixed'
    temp.style.left = '-9999px'
    temp.innerText = sheet.description || ''
    document.body.appendChild(temp)
    const canvas = await html2canvas(temp)
    const imgData = canvas.toDataURL('image/png')
    const pdf = new jsPDF('p', 'mm', 'a4')
    const pageWidth = pdf.internal.pageSize.getWidth()
    const pageHeight = pdf.internal.pageSize.getHeight()
    pdf.addImage(imgData, 'PNG', 0, 0, pageWidth, pageHeight)
    pdf.save(`${sheet.title.replace(/\s+/g, '-')}.pdf`)
    document.body.removeChild(temp)
  }

  return (
    <main className="mx-auto max-w-7xl p-6">
      <h1 className="text-3xl font-bold mb-4">{t('sidebar.categories')}</h1>
      {loading && <div className="text-gray-400">Loading...</div>}
      <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
        {sheets.map((s) => (
          <CheatsheetCard key={s._id} sheet={s} onExportMD={exportMD} onExportPDF={exportPDF} />
        ))}
        {sheets.length === 0 && !loading && (
          <div className="text-gray-400">No cheatsheets in this category.</div>
        )}
      </div>
    </main>
  )
}