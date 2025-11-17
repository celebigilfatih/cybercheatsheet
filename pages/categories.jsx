import { useEffect, useState } from 'react'
import { authFetch } from '../lib/client'

export default function Categories() {
  const [categories, setCategories] = useState([])
  const [loading, setLoading] = useState(true)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')

  const load = async () => {
    setLoading(true)
    const res = await fetch('/api/categories')
    const data = await res.json()
    setCategories(data.categories || [])
    setLoading(false)
  }

  useEffect(() => { load() }, [])

  const add = async () => {
    const res = await authFetch('/api/categories', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, description })
    })
    if (res.ok) {
      setName(''); setDescription(''); load()
    } else {
      const d = await res.json(); alert(d.error || 'Failed to add')
    }
  }

  const update = async (id, next) => {
    const res = await authFetch(`/api/categories/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(next)
    })
    if (res.ok) load(); else { const d = await res.json(); alert(d.error || 'Failed to update') }
  }

  const remove = async (id) => {
    if (!confirm('Delete this category?')) return
    const res = await authFetch(`/api/categories/${id}`, { method: 'DELETE' })
    if (res.ok) load(); else { const d = await res.json(); alert(d.error || 'Failed to delete') }
  }

  return (
    <main className="mx-auto max-w-5xl p-6 space-y-4">
      <h1 className="text-xl font-semibold">Manage Categories</h1>
      <div className="panel p-4 grid md:grid-cols-2 gap-4">
        <div className="space-y-3">
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Name" className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-800" />
          <input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Description" className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-800" />
          <button onClick={add} className="btn-primary">Add Category</button>
        </div>
      </div>

      <div className="panel p-4">
        <h2 className="text-sm font-semibold mb-3">Existing Categories</h2>
        {loading && <div className="text-gray-400">Loading...</div>}
        <ul className="space-y-2">
          {categories.map((c) => (
            <li key={c._id} className="flex items-center gap-2">
              <input defaultValue={c.name} onBlur={(e) => update(c._id, { name: e.target.value, description: c.description })} className="px-2 py-1 rounded bg-gray-900 border border-gray-800" />
              <input defaultValue={c.description} onBlur={(e) => update(c._id, { name: c.name, description: e.target.value })} className="flex-1 px-2 py-1 rounded bg-gray-900 border border-gray-800" />
              <button onClick={() => remove(c._id)} className="btn-secondary">Delete</button>
            </li>
          ))}
          {categories.length === 0 && !loading && <li className="text-gray-400">No categories yet.</li>}
        </ul>
      </div>
    </main>
  )
}