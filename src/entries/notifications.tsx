import { createRoot, render } from '@wordpress/element';
import NotificationsPage from '../NotificationsPage';
import { WebCareShell } from '../components/WebCareShell';
import { apiRequest } from '../utils/api';

function mountNotifications() {
  const container = document.getElementById('webcare-scanner-root') || document.getElementById('webcare-pro-root');
  if (!container) return;

  const app = (
    <WebCareShell activeTab="notifications">
      <NotificationsPage
        apiRequest={apiRequest}
        onNavigateToSettings={() => {
          window.location.href = 'admin.php?page=webcare-pro-settings&tab=webhooks';
        }}
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
  document.addEventListener('DOMContentLoaded', mountNotifications);
} else {
  mountNotifications();
}
