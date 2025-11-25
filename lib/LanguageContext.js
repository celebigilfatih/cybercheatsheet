import { createContext, useContext, useState, useEffect } from 'react'

const LanguageContext = createContext()

export const translations = {
  tr: {
    // Header
    'header.title': 'CyberSec Cheatsheet',
    'header.subtitle': 'Organize your security docs',
    'header.categories': 'Kategoriler',
    'header.login': 'Giriş Yap',
    'header.logout': 'Çıkış Yap',
    'header.lightMode': 'Aydınlık Mod',
    'header.darkMode': 'Karanlık Mod',
    
    // Sidebar
    'sidebar.categories': 'Kategoriler',
    'sidebar.manage': 'Yönet',
    'sidebar.new': 'Yeni',
    'sidebar.all': 'Tümü',
    
    // Search
    'search.placeholder': 'Başlık, etiket, içerik ara',
    'search.filterByTag': 'Etikete göre filtrele',
    'search.button': 'Ara',
    'search.newCheatsheet': 'Yeni Cheatsheet',
    'search.loading': 'Yükleniyor...',
    'search.noResults': 'Cheatsheet bulunamadı. Yeni bir tane oluşturmayı deneyin.',
    
    // Cheatsheet Card
    'card.exportMD': 'MD İndir',
    'card.exportPDF': 'PDF İndir',
    'card.updated': 'Güncellendi',
    
    // Cheatsheet Detail
    'detail.exportMD': 'MD İndir',
    'detail.exportPDF': 'PDF İndir',
    'detail.edit': 'Düzenle',
    'detail.delete': 'Sil',
    'detail.deleteConfirm': 'Bu cheatsheet\'i silmek istediğinizden emin misiniz?',
    'detail.links': 'Bağlantılar',
    'detail.copy': 'Kopyala',
    'detail.copied': 'Kopyalandı!',
    'detail.notFound': 'Bulunamadı',
    'detail.loading': 'Yükleniyor...',
    
    // Categories
    'categories.manage': 'Kategorileri Yönet',
    'categories.name': 'İsim',
    'categories.description': 'Açıklama',
    'categories.add': 'Kategori Ekle',
    'categories.existing': 'Mevcut Kategoriler',
    'categories.noCategories': 'Henüz kategori yok.',
    'categories.delete': 'Sil',
    'categories.deleteConfirm': 'Bu kategoriyi silmek istediğinizden emin misiniz?',
    
    // New/Edit Cheatsheet
    'new.title': 'Yeni Cheatsheet',
    'new.titlePlaceholder': 'Başlık',
    'new.selectCategory': 'Kategori Seçin',
    'new.tags': 'Etiketler (virgülle ayrılmış)',
    'new.links': 'Bağlantılar (virgülle ayrılmış URL\'ler)',
    'new.template': 'Şablon ekle',
    'new.selectTemplate': 'Şablon seçin',
    'new.addTemplate': 'Ekle (Sonuna)',
    'new.replaceTemplate': 'Değiştir (Tamamını)',
    'new.save': 'Cheatsheet Kaydet',
    'new.saving': 'Kaydediliyor...',
    'new.cancel': 'İptal',
    
    'edit.title': 'Cheatsheet Düzenle',
    'edit.save': 'Değişiklikleri Kaydet',
    
    // Login
    'login.title': 'Giriş Yap',
    'login.username': 'Kullanıcı Adı',
    'login.password': 'Şifre',
    'login.loginButton': 'Giriş Yap',
    'login.loggingIn': 'Giriş yapılıyor...',
    'login.logoutButton': 'Çıkış Yap',
    'login.authDisabled': 'Kimlik doğrulama devre dışı. Giriş yapmadan uygulamayı kullanabilirsiniz.',
    'login.loginFailed': 'Giriş başarısız',
    'login.loggedOut': 'Çıkış yapıldı. Token temizlendi.',
  },
  en: {
    // Header
    'header.title': 'CyberSec Cheatsheet',
    'header.subtitle': 'Organize your security docs',
    'header.categories': 'Categories',
    'header.login': 'Login',
    'header.logout': 'Logout',
    'header.lightMode': 'Light Mode',
    'header.darkMode': 'Dark Mode',
    
    // Sidebar
    'sidebar.categories': 'Categories',
    'sidebar.manage': 'Manage',
    'sidebar.new': 'New',
    'sidebar.all': 'All',
    
    // Search
    'search.placeholder': 'Search title, tags, content',
    'search.filterByTag': 'Filter by tag',
    'search.button': 'Search',
    'search.newCheatsheet': 'New Cheatsheet',
    'search.loading': 'Loading...',
    'search.noResults': 'No cheatsheets found. Try creating one.',
    
    // Cheatsheet Card
    'card.exportMD': 'Export MD',
    'card.exportPDF': 'Export PDF',
    'card.updated': 'Updated',
    
    // Cheatsheet Detail
    'detail.exportMD': 'Export MD',
    'detail.exportPDF': 'Export PDF',
    'detail.edit': 'Edit',
    'detail.delete': 'Delete',
    'detail.deleteConfirm': 'Delete this cheatsheet?',
    'detail.links': 'Links',
    'detail.copy': 'Copy',
    'detail.copied': 'Copied!',
    'detail.notFound': 'Not found',
    'detail.loading': 'Loading...',
    
    // Categories
    'categories.manage': 'Manage Categories',
    'categories.name': 'Name',
    'categories.description': 'Description',
    'categories.add': 'Add Category',
    'categories.existing': 'Existing Categories',
    'categories.noCategories': 'No categories yet.',
    'categories.delete': 'Delete',
    'categories.deleteConfirm': 'Delete this category?',
    
    // New/Edit Cheatsheet
    'new.title': 'New Cheatsheet',
    'new.titlePlaceholder': 'Title',
    'new.selectCategory': 'Select Category',
    'new.tags': 'Tags (comma-separated)',
    'new.links': 'Links (comma-separated URLs)',
    'new.template': 'Add template',
    'new.selectTemplate': 'Select template',
    'new.addTemplate': 'Add (Append)',
    'new.replaceTemplate': 'Replace (All)',
    'new.save': 'Save Cheatsheet',
    'new.saving': 'Saving...',
    'new.cancel': 'Cancel',
    
    'edit.title': 'Edit Cheatsheet',
    'edit.save': 'Save Changes',
    
    // Login
    'login.title': 'Login',
    'login.username': 'Username',
    'login.password': 'Password',
    'login.loginButton': 'Login',
    'login.loggingIn': 'Logging in...',
    'login.logoutButton': 'Logout',
    'login.authDisabled': 'Authentication is disabled. You can use the app without login.',
    'login.loginFailed': 'Login failed',
    'login.loggedOut': 'Logged out. Token cleared.',
  }
}

export function LanguageProvider({ children }) {
  const [language, setLanguage] = useState('tr')

  useEffect(() => {
    const saved = localStorage.getItem('language') || 'tr'
    setLanguage(saved)
  }, [])

  const changeLanguage = (lang) => {
    setLanguage(lang)
    localStorage.setItem('language', lang)
  }

  const t = (key) => {
    return translations[language]?.[key] || key.split('.').pop()
  }

  return (
    <LanguageContext.Provider value={{ language, changeLanguage, t }}>
      {children}
    </LanguageContext.Provider>
  )
}

export function useLanguage() {
  const context = useContext(LanguageContext)
  if (!context) {
    throw new Error('useLanguage must be used within LanguageProvider')
  }
  return context
}
