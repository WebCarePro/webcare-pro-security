/**
 * WebCare Pro Security Suite - Unified Theme Controller
 * Ensures absolute synchronization of data-theme, CSS classes across
 * document.documentElement (html), document.body, and #webcare-scanner-root.
 */

export function getWebCareTheme(): 'dark' | 'light' {
  try {
    const saved = localStorage.getItem('webcare_theme_mode');
    if (saved === 'dark' || saved === 'light') {
      return saved;
    }
  } catch {}
  return 'light';
}

export function applyWebCareTheme(mode: 'dark' | 'light'): void {
  try {
    localStorage.setItem('webcare_theme_mode', mode);
  } catch {}

  const isDark = mode === 'dark';
  const rootEl = document.documentElement;
  const bodyEl = document.body;
  const containerRoot = document.getElementById('webcare-scanner-root');

  rootEl.setAttribute('data-theme', isDark ? 'dark' : 'light');

  if (isDark) {
    rootEl.classList.add('webcare-theme-dark');
    rootEl.classList.remove('webcare-theme-light');
    if (bodyEl) {
      bodyEl.classList.add('webcare-theme-dark');
      bodyEl.classList.remove('webcare-theme-light');
    }
    if (containerRoot) {
      containerRoot.classList.add('webcare-theme-dark');
      containerRoot.classList.remove('webcare-theme-light');
    }
  } else {
    rootEl.classList.remove('webcare-theme-dark');
    rootEl.classList.add('webcare-theme-light');
    if (bodyEl) {
      bodyEl.classList.remove('webcare-theme-dark');
      bodyEl.classList.add('webcare-theme-light');
    }
    if (containerRoot) {
      containerRoot.classList.remove('webcare-theme-dark');
      containerRoot.classList.add('webcare-theme-light');
    }
  }
}
