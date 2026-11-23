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
        onNavigateToServerTelemetry={() => { window.location.href = 'admin.php?page=webcare-pro-firewall&tab=server'; }}
        onSubTabChange={(sub, section) => {
          try {
            const url = new URL(window.location.href);
            const canonicalSub = sub === 'rules' ? 'rules' : sub === 'custom_rules' ? 'custom-rules' : sub === 'behavioral' ? 'bots' : sub === 'caf' ? 'adaptive' : sub === 'vpatch' ? 'virtual-patches' : sub === 'ai_defense' ? 'ai-defense' : sub === 'supply_chain' ? 'supply-chain' : sub === 'server_sec' ? 'server' : sub === 'stream' ? 'traffic' : sub;
            url.searchParams.set('tab', canonicalSub);
            if (section) {
              url.searchParams.set('section', section);
            } else {
              url.searchParams.delete('section');
            }
            url.searchParams.delete('subtab');
            window.history.pushState({ tab: canonicalSub, section }, '', url.toString());
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
