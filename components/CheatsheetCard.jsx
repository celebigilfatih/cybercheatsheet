import Link from 'next/link'
import PropTypes from 'prop-types'
import { useLanguage } from '../lib/LanguageContext'

export default function CheatsheetCard({ sheet, onExportMD, onExportPDF }) {
  const { t, language } = useLanguage()
  
  return (
    <div className="panel p-4">
      <div className="flex items-center justify-between">
        <Link href={`/cheatsheet/${sheet._id}`} className="text-lg font-semibold hover:underline">
          {sheet.title?.[language] || sheet.title?.tr || sheet.title}
        </Link>
        <div className="flex gap-2">
          <button onClick={() => onExportMD(sheet)} className="btn-secondary text-xs">{t('card.exportMD')}</button>
          <button onClick={() => onExportPDF(sheet)} className="btn-primary text-xs">{t('card.exportPDF')}</button>
        </div>
      </div>
      <div className="mt-2">
        {sheet.tags?.map((t) => (
          <span key={t} className="tag">#{t}</span>
        ))}
      </div>
      <div className="mt-2 text-sm text-gray-300">
        <span>{t('card.updated')}: {new Date(sheet.updatedAt).toLocaleString()}</span>
      </div>
    </div>
  )
}

CheatsheetCard.propTypes = {
  sheet: PropTypes.shape({
    _id: PropTypes.string.isRequired,
    title: PropTypes.string.isRequired,
    updatedAt: PropTypes.string,
    tags: PropTypes.arrayOf(PropTypes.string)
  }).isRequired,
  onExportMD: PropTypes.func.isRequired,
  onExportPDF: PropTypes.func.isRequired
}