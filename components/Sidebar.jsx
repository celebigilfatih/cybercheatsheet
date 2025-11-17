import useSWR from 'swr'
import PropTypes from 'prop-types'

const fetcher = (url) => fetch(url).then((r) => r.json())

export default function Sidebar({ onSelectCategory, activeCategory }) {
  const { data, error } = useSWR('/api/categories', fetcher)
  const categories = data?.categories || []

  return (
    <aside className="w-64 flex-shrink-0 p-4 border-r border-gray-800">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-sm font-semibold text-gray-300">Categories</h2>
        <div className="flex items-center gap-2">
          <a href="/categories" className="text-xs text-gray-400 hover:underline">Manage</a>
          <a href="/new" className="text-xs text-cyber-accent hover:underline">New</a>
        </div>
      </div>
      <ul className="space-y-1">
        <li>
          <button
            className={`w-full text-left px-2 py-2 rounded hover:bg-gray-800 ${!activeCategory ? 'bg-gray-800' : ''}`}
            onClick={() => onSelectCategory(null)}
          >
            All
          </button>
        </li>
        {categories.map((c) => (
          <li key={c._id}>
            <button
              className={`w-full text-left px-2 py-2 rounded hover:bg-gray-800 ${activeCategory === c._id ? 'bg-gray-800' : ''}`}
              onClick={() => onSelectCategory(c._id)}
            >
              {c.name}
            </button>
          </li>
        ))}
      </ul>
    </aside>
  )
}

Sidebar.propTypes = {
  onSelectCategory: PropTypes.func.isRequired,
  activeCategory: PropTypes.string
}