/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    './pages/**/*.{js,jsx}',
    './components/**/*.{js,jsx}',
    './app/**/*.{js,jsx}'
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#0b0f12',
          panel: '#12171d',
          accent: '#00e5ff',
          accent2: '#8a2be2'
        }
      }
    }
  },
  plugins: [require('@tailwindcss/typography')]
}