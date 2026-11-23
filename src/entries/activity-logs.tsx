import { createRoot, render } from '@wordpress/element';
import { ActivityLogsPage } from '../ActivityLogs/ActivityLogsPage';
import { WebCareShell } from '../components/WebCareShell';
import { apiRequest } from '../utils/api';

function mountActivityLogs() {
  const container = document.getElementById('webcare-scanner-root') || document.getElementById('webcare-pro-root');
  if (!container) return;

  const app = (
    <WebCareShell activeTab="activity_logs">
      <ActivityLogsPage
        apiRequest={apiRequest}
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
  document.addEventListener('DOMContentLoaded', mountActivityLogs);
} else {
  mountActivityLogs();
}
