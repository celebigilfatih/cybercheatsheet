import { useEffect, useState } from 'react'
import { authFetch, getToken } from '../lib/client'
import { useLanguage } from '../lib/LanguageContext'
import Link from 'next/link'

export default function Categories() {
  const { language } = useLanguage()
  const [categories, setCategories] = useState([])
  const [loading, setLoading] = useState(true)
  const [nameEn, setNameEn] = useState('')
  const [nameTr, setNameTr] = useState('')
  const [descEn, setDescEn] = useState('')
  const [descTr, setDescTr] = useState('')
  const [isLoggedIn, setIsLoggedIn] = useState(false)

  const load = async () => {
    setLoading(true)
    try {
      const res = await fetch('/api/categories')
      const data = await res.json()
      setCategories(data.categories || [])
    } catch (err) {
      console.error('Failed to load categories:', err)
    }
    setLoading(false)
  }

  useEffect(() => {
    setIsLoggedIn(!!getToken())
    load()
  }, [])

  const add = async () => {
    if (!nameEn || !nameTr) {
      alert('Please fill in both English and Turkish names')
      return
    }

    const res = await authFetch('/api/categories', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ nameEn, nameTr, descEn, descTr })
    })

    if (res.ok) {
      setNameEn('')
      setNameTr('')
      setDescEn('')
      setDescTr('')
      load()
      alert('Category added successfully!')
    } else {
      const d = await res.json()
      alert(d.error || 'Failed to add category')
    }
  }

  const update = async (id, updatedData) => {
    const res = await authFetch(`/api/categories/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updatedData)
    })

    if (res.ok) {
      load()
    } else {
      const d = await res.json()
      alert(d.error || 'Failed to update')
    }
  }

  const remove = async (id) => {
    if (!confirm('Delete this category?')) return
    const res = await authFetch(`/api/categories/${id}`, { method: 'DELETE' })
    if (res.ok) {
      load()
      alert('Category deleted successfully!')
    } else {
      const d = await res.json()
      alert(d.error || 'Failed to delete')
    }
  }

  if (!isLoggedIn) {
    return (
      <main className="mx-auto max-w-5xl p-6 space-y-4">
        <h1 className="text-xl font-semibold">Manage Categories</h1>
        <div className="panel p-4 bg-yellow-900 text-yellow-200">
          <p>You need to be logged in to manage categories.</p>
          <Link href="/login" className="btn-primary mt-4 inline-block">
            Go to Login
          </Link>
        </div>
      </main>
    )
  }

  return (
    <main className="mx-auto max-w-5xl p-6 space-y-4">
      <h1 className="text-xl font-semibold">Manage Categories</h1>
      <div className="panel p-4 grid md:grid-cols-2 gap-4">
        <div className="space-y-3">
          <input
            value={nameEn}
            onChange={(e) => setNameEn(e.target.value)}
            placeholder="Name (English)"
            className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-800 text-white"
          />
          <input
            value={nameTr}
            onChange={(e) => setNameTr(e.target.value)}
            placeholder="Name (Turkish)"
            className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-800 text-white"
          />
          <input
            value={descEn}
            onChange={(e) => setDescEn(e.target.value)}
            placeholder="Description (English)"
            className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-800 text-white"
          />
          <input
            value={descTr}
            onChange={(e) => setDescTr(e.target.value)}
            placeholder="Description (Turkish)"
            className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-800 text-white"
          />
          <button onClick={add} className="btn-primary w-full">
            Add Category
          </button>
        </div>
      </div>

      <div className="panel p-4">
        <h2 className="text-sm font-semibold mb-3">Existing Categories</h2>
        {loading && <div className="text-gray-400">Loading...</div>}
        <ul className="space-y-3">
          {categories.map((c) => (
            <li key={c.id} className="border border-gray-700 p-3 rounded space-y-2">
              <div className="grid grid-cols-2 gap-2">
                <input
                  defaultValue={c.nameEn || ''}
                  onBlur={(e) =>
                    update(c.id, {
                      nameEn: e.target.value,
                      nameTr: c.nameTr,
                      descEn: c.descEn,
                      descTr: c.descTr
                    })
                  }
                  placeholder="Name (English)"
                  className="px-2 py-1 rounded bg-gray-900 border border-gray-800 text-white"
                />
                <input
                  defaultValue={c.nameTr || ''}
                  onBlur={(e) =>
                    update(c.id, {
                      nameEn: c.nameEn,
                      nameTr: e.target.value,
                      descEn: c.descEn,
                      descTr: c.descTr
                    })
                  }
                  placeholder="Name (Turkish)"
                  className="px-2 py-1 rounded bg-gray-900 border border-gray-800 text-white"
                />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <input
                  defaultValue={c.descEn || ''}
                  onBlur={(e) =>
                    update(c.id, {
                      nameEn: c.nameEn,
                      nameTr: c.nameTr,
                      descEn: e.target.value,
                      descTr: c.descTr
                    })
                  }
                  placeholder="Description (English)"
                  className="px-2 py-1 rounded bg-gray-900 border border-gray-800 text-white"
                />
                <input
                  defaultValue={c.descTr || ''}
                  onBlur={(e) =>
                    update(c.id, {
                      nameEn: c.nameEn,
                      nameTr: c.nameTr,
                      descEn: c.descEn,
                      descTr: e.target.value
                    })
                  }
                  placeholder="Description (Turkish)"
                  className="px-2 py-1 rounded bg-gray-900 border border-gray-800 text-white"
                />
              </div>
              <button onClick={() => remove(c.id)} className="btn-secondary">
                Delete
              </button>
            </li>
          ))}
          {categories.length === 0 && !loading && (
            <li className="text-gray-400">No categories yet.</li>
          )}
        </ul>
      </div>
    </main>
  )
}
