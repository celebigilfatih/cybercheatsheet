import mongoose from 'mongoose'

const CheatsheetSchema = new mongoose.Schema(
  {
    title: {
      tr: { type: String, required: true, trim: true },
      en: { type: String, required: true, trim: true }
    },
    description: {
      tr: { type: String, default: '' },
      en: { type: String, default: '' }
    },
    tags: { type: [String], default: [] },
    links: { type: [String], default: [] },
    category: { type: mongoose.Schema.Types.ObjectId, ref: 'Category', required: true }
  },
  { timestamps: true }
)

// Full-text index for search (both languages)
CheatsheetSchema.index({ 'title.tr': 'text', 'title.en': 'text', 'description.tr': 'text', 'description.en': 'text', tags: 'text' })

export default mongoose.models.Cheatsheet || mongoose.model('Cheatsheet', CheatsheetSchema)