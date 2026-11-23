import { Component, createRoot, render } from '@wordpress/element';
import { SettingsPage } from '../SettingsPage';
import { WebCareShell } from '../components/WebCareShell';
import { apiRequest } from '../utils/api';
import { PILLAR_MAP } from '../utils/routeRegistry';

class SettingsErrorBoundary extends Component<{ children: any }, { hasError: boolean; error: Error | null }> {
  constructor(props: { children: any }) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: any) {
    console.error('Settings Page ErrorBoundary caught:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          margin: '24px 20px 24px 0',
          padding: '24px',
          background: '#ffffff',
          border: '1px solid #fee2e2',
          borderLeft: '4px solid #ef4444',
          borderRadius: '12px',
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.05)',
        }}>
          <h3 style={{ margin: '0 0 8px 0', color: '#991b1b', fontSize: '17px', fontWeight: 700 }}>
            ⚠️ WebCare Pro Settings &amp; Doctor Encountered an Issue
          </h3>
          <p style={{ margin: '0 0 16px 0', color: '#475569', fontSize: '13.5px' }}>
            {this.state.error?.message || 'An unexpected rendering error occurred.'}
          </p>
          <div style={{ display: 'flex', gap: '10px' }}>
            <button
              type="button"
              className="button button-primary"
              style={{ background: '#4f46e5', borderColor: '#4338ca', fontWeight: 600 }}
              onClick={() => {
                this.setState({ hasError: false, error: null });
                window.location.href = 'admin.php?page=webcare-pro-settings';
              }}
            >
              Recover View
            </button>
            <button
              type="button"
              className="button"
              onClick={() => window.location.reload()}
            >
              Reload Page
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

function mountSettings() {
  const container = document.getElementById('webcare-scanner-root') || document.getElementById('webcare-pro-root');
  if (!container) return;

  const urlParams = new URLSearchParams(window.location.search);
  const defaultTab = PILLAR_MAP['webcare-pro-settings']?.default_tab || 'doctor';
  const tabParam = (urlParams.get('tab') as any) || defaultTab;

  const app = (
    <SettingsErrorBoundary>
      <WebCareShell activeTab="settings">
        <SettingsPage
          apiRequest={apiRequest}
          initialSubTab={tabParam}
          onNavigateToDashboard={() => { window.location.href = 'admin.php?page=webcare-pro-security'; }}
          onNavigateToNotifications={() => { window.location.href = 'admin.php?page=webcare-pro-settings&tab=alerts'; }}
          onNavigateToActivityLogs={() => { window.location.href = 'admin.php?page=webcare-pro-logs&tab=activity'; }}
          onNavigateToCronManager={() => { window.location.href = 'admin.php?page=webcare-pro-settings&tab=cron'; }}
        />
      </WebCareShell>
    </SettingsErrorBoundary>
  );

  if (typeof createRoot === 'function') {
    createRoot(container).render(app);
  } else if (typeof render === 'function') {
    render(app, container);
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', mountSettings);
} else {
  mountSettings();
}
