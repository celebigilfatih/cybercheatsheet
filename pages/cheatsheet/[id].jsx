import { useEffect, useState } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import remarkSlug from 'remark-slug'
import remarkToc from 'remark-toc'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { oneDark } from 'react-syntax-highlighter/dist/esm/styles/prism'
import Mermaid from '../../components/Mermaid'
import { useLanguage } from '../../lib/LanguageContext'

import { getToken } from '../../lib/client'

export default function CheatsheetDetail() {
  const [sheet, setSheet] = useState(null)
  const [loading, setLoading] = useState(true)
  const [isLoggedIn, setIsLoggedIn] = useState(false)
  const { t, language } = useLanguage()

  useEffect(() => {
    const token = getToken()
    setIsLoggedIn(!!token)
    const id = window.location.pathname.split('/').pop()
    fetch(`/api/cheatsheets/${id}`).then((r) => r.json()).then((d) => {
      setSheet(d.cheatsheet)
      setLoading(false)
    })
  }, [])

  useEffect(() => {
    // Enhance preview with copy buttons once content is available
    if (!sheet) return
    const container = document.getElementById('sheet-preview')
    if (!container) return
    const blocks = container.querySelectorAll('pre')
    blocks.forEach((pre) => {
      if (pre.querySelector('.copy-btn')) return
      const btn = document.createElement('button')
      btn.textContent = t('detail.copy')
      btn.className = 'copy-btn btn-secondary absolute right-2 top-2 text-xs'
      btn.addEventListener('click', () => {
        const code = pre.querySelector('code')
        const text = code ? code.textContent : ''
        navigator.clipboard.writeText(text || '')
        btn.textContent = t('detail.copied')
        setTimeout(() => (btn.textContent = t('detail.copy')), 1200)
      })
      pre.style.position = 'relative'
      pre.appendChild(btn)
    })
  }, [sheet, t])

  const remove = async () => {
    if (!sheet) return
    if (!confirm(t('detail.deleteConfirm'))) return
    const { authFetch } = await import('../../lib/client')
    const res = await authFetch(`/api/cheatsheets/${sheet._id}`, { method: 'DELETE' })
    if (res.ok) {
      window.location.href = '/'
    } else {
      const d = await res.json()
      alert(d.error || 'Failed to delete')
    }
  }

  const exportMD = () => {
    const content = language === 'en' 
      ? (sheet?.descEn || sheet?.description?.[language] || sheet?.description?.tr || sheet?.description || '')
      : (sheet?.descTr || sheet?.description?.[language] || sheet?.description?.tr || sheet?.description || '')
    const blob = new Blob([content], { type: 'text/markdown;charset=utf-8' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    const title = sheet?.titleEn || sheet?.title?.[language] || sheet?.title?.tr || sheet?.title || 'cheatsheet'
    a.download = `${title.replace(/\s+/g, '-')}.md`
    a.click()
  }

  const exportPDF = async () => {
    const { jsPDF } = await import('jspdf')
    const { default: html2canvas } = await import('html2canvas')
    const container = document.getElementById('sheet-preview')
    const canvas = await html2canvas(container)
    const imgData = canvas.toDataURL('image/png')
    const pdf = new jsPDF('p', 'mm', 'a4')
    const pageWidth = pdf.internal.pageSize.getWidth()
    const pageHeight = pdf.internal.pageSize.getHeight()
    pdf.addImage(imgData, 'PNG', 0, 0, pageWidth, pageHeight)
    pdf.save(`${sheet.title.replace(/\s+/g, '-')}.pdf`)
  }

  if (loading) return <main className="p-6">{t('detail.loading')}</main>
  if (!sheet) return <main className="p-6">{t('detail.notFound')}</main>

  const displayTitle = sheet.titleEn || sheet.title?.[language] || sheet.title?.tr || sheet.title
  const displayContent = language === 'en' 
    ? (sheet.descEn || sheet.description?.[language] || sheet.description?.tr || sheet.description || '')
    : (sheet.descTr || sheet.description?.[language] || sheet.description?.tr || sheet.description || '')

  return (
    <main className="mx-auto max-w-5xl p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-4xl font-bold">{displayTitle}</h1>
        <div className="flex gap-2">
          <button onClick={exportMD} className="btn-secondary">{t('detail.exportMD')}</button>
          <button onClick={exportPDF} className="btn-primary">{t('detail.exportPDF')}</button>
          {isLoggedIn && (
            <>
              <a href={`/cheatsheet/${sheet.id || sheet._id}/edit`} className="btn-secondary">{t('detail.edit')}</a>
              <button onClick={remove} className="btn-secondary">{t('detail.delete')}</button>
            </>
          )}
        </div>
      </div>
      <div className="mt-2">
        {sheet.tags?.map((t) => (<span key={t} className="tag">#{t}</span>))}
      </div>
      <div id="sheet-preview" className="panel p-4 prose prose-invert max-w-none">
        {typeof window !== 'undefined' && (
          <ReactMarkdown
            remarkPlugins={[remarkGfm, remarkSlug, remarkToc]}
            components={{
              code({ inline, className, children, ...props }) {
                const match = /language-(\w+)/.exec(className || '')
                if (!inline && match && match[1] === 'mermaid') {
                  return <Mermaid chart={String(children)} theme="dark" />
                }
                return !inline && match ? (
                  <SyntaxHighlighter style={oneDark} language={match[1]} PreTag="div" {...props}>
                    {String(children).replace(/\n$/, '')}
                  </SyntaxHighlighter>
                ) : (
                  <code className={className} {...props}>
                    {children}
                  </code>
                )
              }
            }}
          >
            {displayContent}
          </ReactMarkdown>
        )}
      </div>
      {sheet.links?.length > 0 && (
        <div className="panel p-4">
          <h2 className="text-sm font-semibold mb-2">{t('detail.links')}</h2>
          <ul className="list-disc ml-6 text-sm">
            {sheet.links.map((l, idx) => (
              <li key={idx}><a className="text-cyber-accent hover:underline" href={l} target="_blank" rel="noreferrer noopener">{l}</a></li>
            ))}
          </ul>
        </div>
      )}
    </main>
  )
}

export async function getServerSideProps() {
  // Force SSR for this page to avoid static pre-render during build,
  // preventing server-side execution of client-only markdown/DOM code.
  return { props: {} }
}