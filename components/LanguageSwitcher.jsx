import { useLanguage } from '../lib/LanguageContext'

export default function LanguageSwitcher() {
  const { language, changeLanguage } = useLanguage()

  return (
    <div className="flex items-center gap-2">
      <button
        onClick={() => changeLanguage('tr')}
        className={`px-3 py-2 rounded font-semibold transition-all ${
          language === 'tr' 
            ? 'bg-cyan-500 text-gray-900' 
            : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
        }`}
        title="Türkçe"
      >
        TR
      </button>
      <button
        onClick={() => changeLanguage('en')}
        className={`px-3 py-2 rounded font-semibold transition-all ${
          language === 'en' 
            ? 'bg-cyan-500 text-gray-900' 
            : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
        }`}
        title="English"
      >
        EN
      </button>
    </div>
  )
}
