import Link from 'next/link'
import PropTypes from 'prop-types'
import { useLanguage } from '../lib/LanguageContext'

export default function CheatsheetCard({ sheet, onExportMD, onExportPDF }) {
  const { t, language } = useLanguage()
  
  const id = sheet.id || sheet._id
  const title = sheet.titleEn || sheet.title?.[language] || sheet.title?.tr || sheet.title
  
  return (
    <div className="panel p-4 space-y-3">
      <div>
        <Link href={`/cheatsheet/${id}`} className="text-lg font-bold text-cyber-accent hover:opacity-80 transition block">
          {title}
        </Link>
      </div>
      
      <div className="flex flex-wrap gap-1">
        {sheet.tags?.map((tag) => (
          <span key={tag} className="tag text-xs"># {tag}</span>
        ))}
      </div>
      
      <div className="text-xs text-gray-400">
        <span>{t('card.updated')}: {new Date(sheet.updatedAt).toLocaleString()}</span>
      </div>
      
      <div className="flex gap-2 pt-2 border-t border-gray-700">
        <button onClick={() => onExportMD(sheet)} className="btn-secondary text-xs flex-1">{t('card.exportMD')}</button>
        <button onClick={() => onExportPDF(sheet)} className="btn-primary text-xs flex-1">{t('card.exportPDF')}</button>
      </div>
    </div>
  )
}

CheatsheetCard.propTypes = {
  sheet: PropTypes.shape({
    id: PropTypes.number,
    _id: PropTypes.string,
    titleEn: PropTypes.string,
    title: PropTypes.oneOfType([PropTypes.string, PropTypes.object]),
    updatedAt: PropTypes.string,
    tags: PropTypes.arrayOf(PropTypes.string)
  }).isRequired,
  onExportMD: PropTypes.func.isRequired,
  onExportPDF: PropTypes.func.isRequired
}
