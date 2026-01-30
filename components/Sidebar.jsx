import useSWR from 'swr'
import PropTypes from 'prop-types'
import { useEffect, useState } from 'react'
import { useLanguage } from '../lib/LanguageContext'
import { getToken } from '../lib/client'
import { 
  HiOutlineFolder,
  HiOutlineFolderOpen,
  HiOutlineCollection,
  HiOutlineCog,
  HiOutlinePlus
} from 'react-icons/hi'

const fetcher = (url) => fetch(url).then((r) => r.json())

export default function Sidebar({ onSelectCategory, activeCategory }) {
  const { data } = useSWR('/api/categories', fetcher)
  const categories = Array.isArray(data?.categories) ? data.categories : []
  const { t, language } = useLanguage()
  const [isLoggedIn, setIsLoggedIn] = useState(false)

  useEffect(() => {
    setIsLoggedIn(!!getToken())
  }, [])

  return (
    <aside className="w-56 flex-shrink-0 bg-cyber-panel/50 border-r border-gray-800/60">
      {/* Header */}
      <div className="px-3 py-3 border-b border-gray-800/60">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-gray-400 uppercase tracking-wider">
            {t('sidebar.categories')}
          </span>
          {isLoggedIn && (
            <div className="flex items-center gap-1">
              <a 
                href="/categories" 
                className="p-1 text-gray-500 hover:text-cyber-accent transition-colors"
                title={t('sidebar.manage')}
              >
                <HiOutlineCog className="w-3.5 h-3.5" />
              </a>
              <a 
                href="/new" 
                className="p-1 text-gray-500 hover:text-cyber-accent transition-colors"
                title={t('sidebar.new')}
              >
                <HiOutlinePlus className="w-3.5 h-3.5" />
              </a>
            </div>
          )}
        </div>
      </div>

      {/* Category List */}
      <nav className="py-1">
        {/* All Categories */}
        <button
          className={`w-full flex items-center gap-2 px-3 py-2 text-sm transition-colors ${
            !activeCategory 
              ? 'text-cyber-accent bg-cyber-accent/10 border-l-2 border-cyber-accent' 
              : 'text-gray-300 hover:bg-gray-800/50 border-l-2 border-transparent'
          }`}
          onClick={() => onSelectCategory(null)}
        >
          <HiOutlineCollection className="w-4 h-4 flex-shrink-0" />
          <span className="truncate">{t('sidebar.all')}</span>
        </button>

        {/* Category Items */}
        {categories.map((c) => {
          const isActive = activeCategory === (c.id || c._id)
          return (
            <button
              key={c.id || c._id}
              className={`w-full flex items-center gap-2 px-3 py-2 text-sm transition-colors ${
                isActive 
                  ? 'text-cyber-accent bg-cyber-accent/10 border-l-2 border-cyber-accent' 
                  : 'text-gray-300 hover:bg-gray-800/50 border-l-2 border-transparent'
              }`}
              onClick={() => onSelectCategory(c.id || c._id)}
            >
              {isActive ? (
                <HiOutlineFolderOpen className="w-4 h-4 flex-shrink-0" />
              ) : (
                <HiOutlineFolder className="w-4 h-4 flex-shrink-0" />
              )}
              <span className="truncate">
                {c.nameEn || c.name?.[language] || c.name?.tr || c.name}
              </span>
            </button>
          )
        })}
      </nav>
    </aside>
  )
}

Sidebar.propTypes = {
  onSelectCategory: PropTypes.func.isRequired,
  activeCategory: PropTypes.oneOfType([PropTypes.string, PropTypes.number])
}
