import { createRoot, render } from '@wordpress/element';
import '../utils/domPatch';
import { CustomRulesStudio } from '../components/CustomRulesStudio';
import { WebCareShell } from '../components/WebCareShell';

function mountModularWaf() {
  const container = document.getElementById('webcare-scanner-root') || document.getElementById('webcare-pro-root');
  if (!container) return;

  const app = (
    <WebCareShell activeTab="custom_rules">
      <CustomRulesStudio />
    </WebCareShell>
  );

  if (typeof createRoot === 'function') {
    createRoot(container).render(app);
  } else if (typeof render === 'function') {
    render(app, container);
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', mountModularWaf);
} else {
  mountModularWaf();
}
