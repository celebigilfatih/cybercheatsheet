import { useEffect, useState } from 'react'
import { authFetch } from '../../../lib/client'

export default function EditCheatsheet() {
  const [sheet, setSheet] = useState(null)
  const [titleEn, setTitleEn] = useState('')
  const [titleTr, setTitleTr] = useState('')
  const [descEn, setDescEn] = useState('')
  const [descTr, setDescTr] = useState('')
  const [tags, setTags] = useState('')
  const [links, setLinks] = useState('')
  const [categoryId, setCategoryId] = useState('')
  const [categories, setCategories] = useState([])
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    const id = window.location.pathname.split('/').slice(-2, -1)[0]
    fetch(`/api/cheatsheets/${id}`).then((r) => r.json()).then((d) => {
      const s = d.cheatsheet
      setSheet(s)
      setTitleEn(s.titleEn || '')
      setTitleTr(s.titleTr || '')
      setDescEn(s.descEn || '')
      setDescTr(s.descTr || '')
      setTags((s.tags || []).join(', '))
      setLinks((s.links || []).join(', '))
      setCategoryId(s.categoryId || '')
    })
    fetch('/api/categories').then((r) => r.json()).then((d) => setCategories(d.categories || []))
  }, [])

  const save = async () => {
    if (!sheet) return
    setSaving(true)
    const res = await authFetch(`/api/cheatsheets/${sheet.id || sheet._id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        titleEn,
        titleTr,
        descriptionEn: descEn,
        descriptionTr: descTr,
        tags: tags.split(',').map((t) => t.trim()).filter(Boolean),
        links: links.split(',').map((l) => l.trim()).filter(Boolean),
        categoryId: parseInt(categoryId, 10)
      })
    })
    const data = await res.json()
    setSaving(false)
    if (res.ok) {
      window.location.href = `/cheatsheet/${data.cheatsheet.id || data.cheatsheet._id}`
    } else {
      alert(data.error || 'Failed to save')
    }
  }

  return (
    <main className="mx-auto max-w-5xl p-6 space-y-4">
      <h1 className="text-xl font-semibold">Edit Cheatsheet</h1>
      <div className="panel p-4 grid md:grid-cols-2 gap-4">
        <div className="space-y-3">
          <div>
            <label className="text-xs text-gray-400">Title (English)</label>
            <input value={titleEn} onChange={(e) => setTitleEn(e.target.value)} placeholder="Title EN" className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-800" />
          </div>
          <div>
            <label className="text-xs text-gray-400">Title (Turkish)</label>
            <input value={titleTr} onChange={(e) => setTitleTr(e.target.value)} placeholder="Title TR" className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-800" />
          </div>
          <select value={categoryId} onChange={(e) => setCategoryId(e.target.value)} className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-800">
            <option value="">Select Category</option>
            {categories.map((c) => (
              <option key={c.id || c._id} value={c.id || c._id}>{c.nameEn || c.name}</option>
            ))}
          </select>
          <input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="Tags (comma-separated)" className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-800" />
          <input value={links} onChange={(e) => setLinks(e.target.value)} placeholder="Links (comma-separated URLs)" className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-800" />
        </div>
        <div className="space-y-3">
          <div>
            <label className="text-xs text-gray-400">Description (English)</label>
            <textarea value={descEn} onChange={(e) => setDescEn(e.target.value)} placeholder="Description EN" rows="10" className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-800 font-mono text-sm" />
          </div>
          <div>
            <label className="text-xs text-gray-400">Description (Turkish)</label>
            <textarea value={descTr} onChange={(e) => setDescTr(e.target.value)} placeholder="Description TR" rows="10" className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-800 font-mono text-sm" />
          </div>
        </div>
      </div>
      <div className="flex gap-2">
        <button onClick={save} className="btn-primary" disabled={saving}>{saving ? 'Saving...' : 'Save Changes'}</button>
        <a href={`/cheatsheet/${sheet?.id || sheet?._id || ''}`} className="btn-secondary">Cancel</a>
      </div>
    </main>
  )
}

export async function getServerSideProps() {
  // Force SSR to avoid static build-time rendering of client-only Markdown editor
  return { props: {} }
}