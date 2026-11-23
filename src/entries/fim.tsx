import { createRoot, render } from '@wordpress/element';
import FileIntegrityPage from '../FileIntegrityPage';
import { WebCareShell } from '../components/WebCareShell';
import { apiRequest } from '../utils/api';

function mountFim() {
  const container = document.getElementById('webcare-scanner-root') || document.getElementById('webcare-pro-root');
  if (!container) return;

  const app = (
    <WebCareShell activeTab="fim">
      <FileIntegrityPage
        apiRequest={apiRequest}
        onNavigateToDashboard={() => { window.location.href = 'admin.php?page=webcare-pro-scanner'; }}
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
  document.addEventListener('DOMContentLoaded', mountFim);
} else {
  mountFim();
}
