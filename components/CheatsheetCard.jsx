import Link from 'next/link'
import PropTypes from 'prop-types'
import { useLanguage } from '../lib/LanguageContext'
import { 
  HiOutlineDocumentText,
  HiOutlineDownload,
  HiOutlineDocumentDownload,
  HiOutlineClock,
  HiOutlineTag
} from 'react-icons/hi'

export default function CheatsheetCard({ sheet, onExportMD, onExportPDF }) {
  const { t, language } = useLanguage()
  
  const id = sheet.id || sheet._id
  const title = sheet.titleEn || sheet.title?.[language] || sheet.title?.tr || sheet.title
  
  // Show only first 3 tags
  const displayTags = sheet.tags?.slice(0, 3) || []
  const remainingTags = (sheet.tags?.length || 0) - 3
  
  return (
    <div className="group bg-cyber-panel/80 rounded-lg border border-gray-800/50 hover:border-cyber-accent/30 transition-all duration-200">
      {/* Card Header */}
      <div className="px-3 py-3 border-b border-gray-800/40">
        <Link 
          href={`/cheatsheet/${id}`} 
          className="flex items-start gap-2 text-gray-100 hover:text-cyber-accent transition-colors"
        >
          <HiOutlineDocumentText className="w-4 h-4 mt-0.5 flex-shrink-0 text-cyber-accent/70" />
          <span className="font-bold text-2xl leading-tight line-clamp-2">{title}</span>
        </Link>
      </div>
      
      {/* Tags */}
      {displayTags.length > 0 && (
        <div className="px-3 py-2 flex items-center gap-1 flex-wrap">
          <HiOutlineTag className="w-3 h-3 text-gray-500 flex-shrink-0" />
          {displayTags.map((tag) => (
            <span 
              key={tag} 
              className="px-1.5 py-0.5 text-[10px] rounded bg-gray-800/60 text-gray-400"
            >
              {tag}
            </span>
          ))}
          {remainingTags > 0 && (
            <span className="text-[10px] text-gray-500">+{remainingTags}</span>
          )}
        </div>
      )}
      
      {/* Footer */}
      <div className="px-3 py-2 flex items-center justify-between border-t border-gray-800/40">
        <div className="flex items-center gap-1 text-[10px] text-gray-500">
          <HiOutlineClock className="w-3 h-3" />
          <span>{new Date(sheet.updatedAt).toLocaleDateString()}</span>
        </div>
        
        <div className="flex items-center gap-1">
          <button 
            onClick={() => onExportMD(sheet)} 
            className="p-1.5 text-gray-400 hover:text-cyber-accent hover:bg-gray-800/50 rounded transition-colors"
            title={t('card.exportMD')}
          >
            <HiOutlineDownload className="w-3.5 h-3.5" />
          </button>
          <button 
            onClick={() => onExportPDF(sheet)} 
            className="p-1.5 text-gray-400 hover:text-cyber-accent hover:bg-gray-800/50 rounded transition-colors"
            title={t('card.exportPDF')}
          >
            <HiOutlineDocumentDownload className="w-3.5 h-3.5" />
          </button>
        </div>
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
