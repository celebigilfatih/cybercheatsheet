import '../styles/globals.css'
import { useEffect, useState } from 'react'
import { getToken, clearToken } from '../lib/client'
import LanguageSwitcher from '../components/LanguageSwitcher'
import { LanguageProvider, useLanguage } from '../lib/LanguageContext'
import Link from 'next/link'

function AppContent({ Component, pageProps }) {
  const [dark, setDark] = useState(true)
  const { t } = useLanguage()

  useEffect(() => {
    const saved = localStorage.getItem('theme')
    const isDark = saved ? saved === 'dark' : true
    setDark(isDark)
    document.documentElement.classList.toggle('dark', isDark)
  }, [])

  const toggle = () => {
    const next = !dark
    setDark(next)
    localStorage.setItem('theme', next ? 'dark' : 'light')
    document.documentElement.classList.toggle('dark', next)
  }

  const logout = () => {
    clearToken()
    alert(t('header.logout'))
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
            <a href="/login" className="btn-secondary">{t('header.login')}</a>
            <button onClick={logout} className="btn-secondary">{t('header.logout')}</button>
            <button onClick={toggle} className="btn-secondary">{dark ? t('header.lightMode') : t('header.darkMode')}</button>
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
