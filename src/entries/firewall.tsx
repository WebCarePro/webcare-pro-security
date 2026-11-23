import { createRoot, render } from '@wordpress/element';
import { FirewallPage } from '../FirewallPage';
import { WebCareShell } from '../components/WebCareShell';
import { apiRequest } from '../utils/api';

function mountFirewall() {
  const container = document.getElementById('webcare-scanner-root') || document.getElementById('webcare-pro-root');
  if (!container) return;

  const urlParams = new URLSearchParams(window.location.search);
  const tabParam = (urlParams.get('tab') as any) || 'stream';

  const app = (
    <WebCareShell activeTab="firewall">
      <FirewallPage
        apiRequest={apiRequest}
        initialSubTab={tabParam}
        onNavigateToDashboard={() => { window.location.href = 'admin.php?page=webcare-pro-security'; }}
        onNavigateToWafLogs={() => { window.location.href = 'admin.php?page=webcare-pro-logs&tab=firewall'; }}
        onNavigateToVpatch={() => { window.location.href = 'admin.php?page=webcare-pro-firewall&tab=virtual-patches'; }}
        onNavigateToSettings={(sub) => { window.location.href = `admin.php?page=webcare-pro-settings&tab=${sub}`; }}
        onNavigateToServerTelemetry={() => { window.location.href = 'admin.php?page=webcare-pro-firewall&tab=server_sec'; }}
        onSubTabChange={(sub) => {
          try {
            const url = new URL(window.location.href);
            const canonicalSub = sub === 'rules' ? 'waf-rules' : sub === 'custom_rules' ? 'custom-waf-rules' : sub;
            url.searchParams.set('tab', canonicalSub);
            window.history.pushState({ tab: canonicalSub }, '', url.toString());
          } catch (e) {}
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
  document.addEventListener('DOMContentLoaded', mountFirewall);
} else {
  mountFirewall();
}
