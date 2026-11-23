import { createRoot, render } from '@wordpress/element';
import { AuthSecurityPage } from '../AuthSecurityPage';
import { WebCareShell } from '../components/WebCareShell';
import { apiRequest } from '../utils/api';

function mountAuth() {
  const container = document.getElementById('webcare-scanner-root') || document.getElementById('webcare-pro-root');
  if (!container) return;

  const urlParams = new URLSearchParams(window.location.search);
  const tabParam = (urlParams.get('tab') as any) || '2fa';

  const app = (
    <WebCareShell activeTab="auth">
      <AuthSecurityPage
        apiRequest={apiRequest}
        initialSubTab={tabParam}
        onNavigateToDashboard={() => { window.location.href = 'admin.php?page=webcare-pro-security'; }}
      />
    </WebCareShell>
  );

  if (typeof createRoot === 'function') {
    createRoot(container).render(app);
  } else if (typeof render === 'function') {
    render(app, container);
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', mountAuth);
} else {
  mountAuth();
}
