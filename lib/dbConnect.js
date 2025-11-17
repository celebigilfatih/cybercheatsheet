import mongoose from 'mongoose'

let cached = global.mongoose

if (!cached) {
  cached = global.mongoose = { conn: null, promise: null }
}

export default async function dbConnect() {
  const uri = process.env.MONGODB_URI || `mongodb://${process.env.MONGODB_HOST || '127.0.0.1'}:${process.env.MONGODB_PORT || '27017'}/${process.env.MONGODB_DB || 'cybersheet'}`

  if (cached.conn) return cached.conn

  if (!cached.promise) {
    cached.promise = mongoose.connect(uri, {
      bufferCommands: false
    }).then((mongoose) => mongoose)
  }
  cached.conn = await cached.promise
  return cached.conn
}