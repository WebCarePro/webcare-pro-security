import { createRoot, render } from '@wordpress/element';
import { WebCareVaultPage } from '../WebCareVaultPage';
import { WebCareShell } from '../components/WebCareShell';
import { apiRequest } from '../utils/api';

function mountVault() {
  const container = document.getElementById('webcare-scanner-root') || document.getElementById('webcare-pro-root');
  if (!container) return;

  const urlParams = new URLSearchParams(window.location.search);
  const tabParam = urlParams.get('tab');
  const pageParam = urlParams.get('page');

  const FORENSICS_TABS = ['persistence', 'watchdog', 'baseline', 'files', 'attack_chain', 'attack-chains', 'correlation', 'whitelist', 'allowlist', 'transactions', 'self_defense', 'self-defense', 'preloaders', 'snapshots'];
  const resolvedTab = (tabParam === 'diagnostics' || tabParam === 'forensics' || (tabParam && FORENSICS_TABS.includes(tabParam)))
    ? 'forensics'
    : (tabParam || (pageParam === 'webcare-pro-server' ? 'server' : (pageParam === 'webcare-pro-forensics' ? 'forensics' : 'database')));

  const app = (
    <WebCareShell activeTab="vault">
      <WebCareVaultPage
        apiRequest={apiRequest}
        initialTab={resolvedTab as any}
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
  document.addEventListener('DOMContentLoaded', mountVault);
} else {
  mountVault();
}
