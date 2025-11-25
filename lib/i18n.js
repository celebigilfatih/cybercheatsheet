import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'

// Inline translations to avoid JSON import issues
const trTranslation = {
  "header": {
    "title": "CyberSec Cheatsheet",
    "subtitle": "Organize your security docs",
    "categories": "Kategoriler",
    "login": "Giriş Yap",
    "logout": "Çıkış Yap",
    "lightMode": "Aydınlık Mod",
    "darkMode": "Karanlık Mod"
  },
  "sidebar": {
    "categories": "Kategoriler",
    "manage": "Yönet",
    "new": "Yeni",
    "all": "Tümü"
  },
  "search": {
    "searchPlaceholder": "Başlık, etiket, içerik ara",
    "filterByTag": "Etikete göre filtrele",
    "search": "Ara",
    "newCheatsheet": "Yeni Cheatsheet",
    "loading": "Yükleniyor...",
    "noResults": "Cheatsheet bulunamadı. Yeni bir tane oluşturmayı deneyin."
  },
  "cheatsheet": {
    "exportMD": "MD İndir",
    "exportPDF": "PDF İndir",
    "edit": "Düzenle",
    "delete": "Sil",
    "deleteConfirm": "Bu cheatsheet'i silmek istediğinizden emin misiniz?",
    "updated": "Güncellendi",
    "links": "Bağlantılar",
    "notFound": "Bulunamadı",
    "copy": "Kopyala",
    "copied": "Kopyalandı!"
  },
  "categories": {
    "manage": "Kategorileri Yönet",
    "name": "İsim",
    "description": "Açıklama",
    "addCategory": "Kategori Ekle",
    "existing": "Mevcut Kategoriler",
    "noCategories": "Henüz kategori yok.",
    "deleteConfirm": "Bu kategoriyi silmek istediğinizden emin misiniz?"
  },
  "common": {
    "loading": "Yükleniyor...",
    "save": "Kaydet",
    "cancel": "İptal",
    "delete": "Sil",
    "edit": "Düzenle",
    "add": "Ekle"
  },
  "newCheatsheet": {
    "title": "Yeni Cheatsheet",
    "titlePlaceholder": "Başlık",
    "selectCategory": "Kategori Seçin",
    "tagsPlaceholder": "Etiketler (virgülle ayrılmış)",
    "linksPlaceholder": "Bağlantılar (virgülle ayrılmış URL'ler)",
    "templateLabel": "Şablon ekle",
    "selectTemplate": "Şablon seçin",
    "addTemplate": "Ekle (Sonuna)",
    "replaceTemplate": "Değiştir (Tamamını)",
    "saving": "Kaydediliyor...",
    "saveCheatsheet": "Cheatsheet Kaydet"
  },
  "editCheatsheet": {
    "title": "Cheatsheet Düzenle",
    "saveChanges": "Değişiklikleri Kaydet"
  },
  "login": {
    "title": "Giriş Yap",
    "username": "Kullanıcı Adı",
    "password": "Şifre",
    "loggingIn": "Giriş yapılıyor...",
    "login": "Giriş Yap",
    "logout": "Çıkış Yap",
    "authDisabled": "Kimlik doğrulama devre dışı. Giriş yapmadan uygulamayı kullanabilirsiniz.",
    "loginFailed": "Giriş başarısız",
    "loggedOut": "Çıkış yapıldı. Token temizlendi."
  }
}

const enTranslation = {
  "header": {
    "title": "CyberSec Cheatsheet",
    "subtitle": "Organize your security docs",
    "categories": "Categories",
    "login": "Login",
    "logout": "Logout",
    "lightMode": "Light Mode",
    "darkMode": "Dark Mode"
  },
  "sidebar": {
    "categories": "Categories",
    "manage": "Manage",
    "new": "New",
    "all": "All"
  },
  "search": {
    "searchPlaceholder": "Search title, tags, content",
    "filterByTag": "Filter by tag",
    "search": "Search",
    "newCheatsheet": "New Cheatsheet",
    "loading": "Loading...",
    "noResults": "No cheatsheets found. Try creating one."
  },
  "cheatsheet": {
    "exportMD": "Export MD",
    "exportPDF": "Export PDF",
    "edit": "Edit",
    "delete": "Delete",
    "deleteConfirm": "Delete this cheatsheet?",
    "updated": "Updated",
    "links": "Links",
    "notFound": "Not found",
    "copy": "Copy",
    "copied": "Copied!"
  },
  "categories": {
    "manage": "Manage Categories",
    "name": "Name",
    "description": "Description",
    "addCategory": "Add Category",
    "existing": "Existing Categories",
    "noCategories": "No categories yet.",
    "deleteConfirm": "Delete this category?"
  },
  "common": {
    "loading": "Loading...",
    "save": "Save",
    "cancel": "Cancel",
    "delete": "Delete",
    "edit": "Edit",
    "add": "Add"
  },
  "newCheatsheet": {
    "title": "New Cheatsheet",
    "titlePlaceholder": "Title",
    "selectCategory": "Select Category",
    "tagsPlaceholder": "Tags (comma-separated)",
    "linksPlaceholder": "Links (comma-separated URLs)",
    "templateLabel": "Add template",
    "selectTemplate": "Select template",
    "addTemplate": "Add (Append)",
    "replaceTemplate": "Replace (All)",
    "saving": "Saving...",
    "saveCheatsheet": "Save Cheatsheet"
  },
  "editCheatsheet": {
    "title": "Edit Cheatsheet",
    "saveChanges": "Save Changes"
  },
  "login": {
    "title": "Login",
    "username": "Username",
    "password": "Password",
    "loggingIn": "Logging in...",
    "login": "Login",
    "logout": "Logout",
    "authDisabled": "Authentication is disabled. You can use the app without login.",
    "loginFailed": "Login failed",
    "loggedOut": "Logged out. Token cleared."
  }
}

const resources = {
  tr: {
    translation: trTranslation
  },
  en: {
    translation: enTranslation
  }
}

// Get saved language from localStorage or default to Turkish
const savedLanguage = typeof window !== 'undefined' 
  ? localStorage.getItem('language') || 'tr'
  : 'tr'

i18n
  .use(initReactI18next)
  .init({
    resources,
    lng: savedLanguage,
    fallbackLng: 'tr',
    interpolation: {
      escapeValue: false
    },
    react: {
      useSuspense: false
    }
  })

export default i18n
