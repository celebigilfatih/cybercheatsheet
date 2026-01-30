import { useEffect, useState } from 'react'
import MarkdownEditor from '../components/MarkdownEditor'
import { TEMPLATE_OPTIONS, getTemplate } from '../lib/templates'
import { authFetch, getToken } from '../lib/client'
import { useLanguage } from '../lib/LanguageContext'

export default function NewCheatsheet() {
  const [titleTr, setTitleTr] = useState('')
  const [titleEn, setTitleEn] = useState('')
  const [descriptionTr, setDescriptionTr] = useState('')
  const [descriptionEn, setDescriptionEn] = useState('')
  const [tags, setTags] = useState('')
  const [links, setLinks] = useState('')
  const [category, setCategory] = useState('')
  const [categories, setCategories] = useState([])
  const [saving, setSaving] = useState(false)
  const [tpl, setTpl] = useState('')
  const { t, language } = useLanguage()

  useEffect(() => {
    if (!getToken()) {
      window.location.href = '/login'
      return
    }
    fetch('/api/categories').then((r) => r.json()).then((d) => setCategories(d.categories || []))
  }, [])

  const save = async () => {
    setSaving(true)
    const res = await authFetch('/api/cheatsheets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title: { tr: titleTr, en: titleEn },
        description: { tr: descriptionTr, en: descriptionEn },
        tags: tags.split(',').map((t) => t.trim()).filter(Boolean),
        links: links.split(',').map((l) => l.trim()).filter(Boolean),
        category
      })
    })
    const data = await res.json()
    setSaving(false)
    if (res.ok) {
      window.location.href = `/cheatsheet/${data.cheatsheet._id}`
    } else {
      alert(data.error || 'Failed to save')
    }
  }

  return (
    <main className="mx-auto max-w-5xl p-6 space-y-4">
      <h1 className="text-3xl font-bold mb-4">{t('new.title')}</h1>
      <div className="panel p-4 space-y-4">
        <div className="grid md:grid-cols-2 gap-4">
          <div className="space-y-2">
            <label className="text-xs text-gray-400">{t('new.titlePlaceholder')} (TR)</label>
            <input value={titleTr} onChange={(e) => setTitleTr(e.target.value)} placeholder="Başlık (Türkçe)" className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-800" />
          </div>
          <div className="space-y-2">
            <label className="text-xs text-gray-400">{t('new.titlePlaceholder')} (EN)</label>
            <input value={titleEn} onChange={(e) => setTitleEn(e.target.value)} placeholder="Title (English)" className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-800" />
          </div>
        </div>
        <div className="space-y-3">
          <select value={category} onChange={(e) => setCategory(e.target.value)} className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-800">
            <option value="">{t('new.selectCategory')}</option>
            {categories.map((c) => (
              <option key={c._id} value={c._id}>{c.name?.[language] || c.name?.tr || c.name}</option>
            ))}
          </select>
          <input value={tags} onChange={(e) => setTags(e.target.value)} placeholder={t('new.tags')} className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-800" />
          <input value={links} onChange={(e) => setLinks(e.target.value)} placeholder={t('new.links')} className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-800" />
          <div className="grid grid-cols-1 gap-2">
            <label className="text-xs text-gray-400">{t('new.template')}</label>
            <div className="flex gap-2">
              <select value={tpl} onChange={(e) => setTpl(e.target.value)} className="flex-1 px-3 py-2 rounded bg-gray-900 border border-gray-800">
                <option value="">{t('new.selectTemplate')}</option>
                {TEMPLATE_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>{o.label}</option>
                ))}
              </select>
              <button
                type="button"
                className="btn-secondary"
                onClick={() => {
                  if (!tpl) return
                  const text = getTemplate(tpl)
                  setDescriptionTr((prev) => prev ? `${prev}\n\n${text}` : text)
                  setDescriptionEn((prev) => prev ? `${prev}\n\n${text}` : text)
                }}
              >{t('new.addTemplate')}</button>
              <button
                type="button"
                className="btn-secondary"
                onClick={() => {
                  if (!tpl) return
                  const text = getTemplate(tpl)
                  setDescriptionTr(text)
                  setDescriptionEn(text)
                }}
              >{t('new.replaceTemplate')}</button>
            </div>
          </div>
        </div>
        <div className="grid md:grid-cols-2 gap-4">
          <div className="space-y-2">
            <label className="text-xs text-gray-400">İçerik (TR)</label>
            <MarkdownEditor value={descriptionTr} onChange={setDescriptionTr} />
          </div>
          <div className="space-y-2">
            <label className="text-xs text-gray-400">Content (EN)</label>
            <MarkdownEditor value={descriptionEn} onChange={setDescriptionEn} />
          </div>
        </div>
      </div>
      <div className="flex gap-2">
        <button onClick={save} className="btn-primary" disabled={saving}>{saving ? t('new.saving') : t('new.save')}</button>
        <a href="/" className="btn-secondary">{t('new.cancel')}</a>
      </div>
    </main>
  )
}

export async function getServerSideProps() {
  // Force SSR to avoid static build-time rendering of client-only Markdown editor
  return { props: {} }
}