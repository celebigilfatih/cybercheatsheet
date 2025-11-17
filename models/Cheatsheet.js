import mongoose from 'mongoose'

const CheatsheetSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true },
    description: { type: String, default: '' },
    tags: { type: [String], default: [] },
    links: { type: [String], default: [] },
    category: { type: mongoose.Schema.Types.ObjectId, ref: 'Category', required: true }
  },
  { timestamps: true }
)

// Full-text index for search
CheatsheetSchema.index({ title: 'text', description: 'text', tags: 'text' })

export default mongoose.models.Cheatsheet || mongoose.model('Cheatsheet', CheatsheetSchema)