import '../index.css';
import '../utils/domPatch';
import { applyWebCareTheme, getWebCareTheme } from '../utils/theme';

/**
 * WebCare Pro Security & Firewall - Global Application Asset
 * Enqueued across all WebCare admin pages to provide the core design system,
 * CSS variables, typography, and theme state.
 */
(function() {
  try {
    applyWebCareTheme(getWebCareTheme());
  } catch (e) {}
})();
