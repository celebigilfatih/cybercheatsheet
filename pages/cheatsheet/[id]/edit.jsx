import { useEffect, useState } from 'react'
import MarkdownEditor from '../../../components/MarkdownEditor'
import { authFetch } from '../../../lib/client'

export default function EditCheatsheet() {
  const [sheet, setSheet] = useState(null)
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [tags, setTags] = useState('')
  const [links, setLinks] = useState('')
  const [category, setCategory] = useState('')
  const [categories, setCategories] = useState([])
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    const id = window.location.pathname.split('/').slice(-2, -1)[0]
    fetch(`/api/cheatsheets/${id}`).then((r) => r.json()).then((d) => {
      const s = d.cheatsheet
      setSheet(s)
      setTitle(s.title)
      setDescription(s.description || '')
      setTags((s.tags || []).join(', '))
      setLinks((s.links || []).join(', '))
      setCategory(s.category || '')
    })
    fetch('/api/categories').then((r) => r.json()).then((d) => setCategories(d.categories || []))
  }, [])

  const save = async () => {
    if (!sheet) return
    setSaving(true)
    const res = await authFetch(`/api/cheatsheets/${sheet._id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title,
        description,
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
      <h1 className="text-xl font-semibold">Edit Cheatsheet</h1>
      <div className="panel p-4 grid md:grid-cols-2 gap-4">
        <div className="space-y-3">
          <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Title" className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-800" />
          <select value={category} onChange={(e) => setCategory(e.target.value)} className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-800">
            <option value="">Select Category</option>
            {categories.map((c) => (
              <option key={c._id} value={c._id}>{c.name}</option>
            ))}
          </select>
          <input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="Tags (comma-separated)" className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-800" />
          <input value={links} onChange={(e) => setLinks(e.target.value)} placeholder="Links (comma-separated URLs)" className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-800" />
        </div>
        <div>
          <MarkdownEditor value={description} onChange={setDescription} />
        </div>
      </div>
      <div className="flex gap-2">
        <button onClick={save} className="btn-primary" disabled={saving}>{saving ? 'Saving...' : 'Save Changes'}</button>
        <a href={`/cheatsheet/${sheet?._id || ''}`} className="btn-secondary">Cancel</a>
      </div>
    </main>
  )
}

export async function getServerSideProps() {
  // Force SSR to avoid static build-time rendering of client-only Markdown editor
  return { props: {} }
}