import mongoose from 'mongoose'

const CategorySchema = new mongoose.Schema(
  {
    name: {
      tr: { type: String, required: true, trim: true },
      en: { type: String, required: true, trim: true }
    },
    description: {
      tr: { type: String, default: '' },
      en: { type: String, default: '' }
    }
  },
  { timestamps: true }
)

export default mongoose.models.Category || mongoose.model('Category', CategorySchema)