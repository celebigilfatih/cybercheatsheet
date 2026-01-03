import '../styles/globals.css'
import { useEffect, useState } from 'react'
import { getToken, clearToken } from '../lib/client'
import LanguageSwitcher from '../components/LanguageSwitcher'
import { LanguageProvider, useLanguage } from '../lib/LanguageContext'
import Link from 'next/link'

function AppContent({ Component, pageProps }) {
  const [isLoggedIn, setIsLoggedIn] = useState(false)
  const { t } = useLanguage()

  useEffect(() => {
    // Check login status on mount
    setIsLoggedIn(!!getToken())
    
    // Listen for storage changes (logout from other tabs)
    const handleStorageChange = () => {
      setIsLoggedIn(!!getToken())
    }
    window.addEventListener('storage', handleStorageChange)
    return () => window.removeEventListener('storage', handleStorageChange)
  }, [])

  const logout = () => {
    clearToken()
    setIsLoggedIn(false)
    alert(t('header.logout') || 'Logged out successfully')
    window.location.href = '/login'
  }

  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-50 border-b border-gray-800 bg-cyber-panel">
        <div className="mx-auto max-w-7xl px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Link href="/" className="text-cyber-accent font-semibold hover:opacity-80 cursor-pointer transition">
              {t('header.title')}
            </Link>
            <span className="text-xs text-gray-400">{t('header.subtitle')}</span>
          </div>
          <div className="flex items-center gap-2">
            <a href="/categories" className="btn-secondary">{t('header.categories')}</a>
            {!isLoggedIn ? (
              <a href="/login" className="btn-secondary">{t('header.login')}</a>
            ) : (
              <button onClick={logout} className="btn-secondary">{t('header.logout')}</button>
            )}
            <LanguageSwitcher />
          </div>
        </div>
      </header>
      <Component {...pageProps} />
    </div>
  )
}

export default function App({ Component, pageProps }) {
  return (
    <LanguageProvider>
      <AppContent Component={Component} pageProps={pageProps} />
    </LanguageProvider>
  )
}
