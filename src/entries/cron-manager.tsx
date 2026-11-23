import { Component, createRoot, render } from '@wordpress/element';
import { CronManagerPage } from '../CronManager/CronManagerPage';
import { WebCareShell } from '../components/WebCareShell';
import { apiRequest } from '../utils/api';

class CronManagerErrorBoundary extends Component<{ children: any }, { hasError: boolean; error: Error | null }> {
  constructor(props: { children: any }) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="notice notice-error" style={{ padding: '16px', margin: '16px 0' }}>
          <h3 style={{ margin: '0 0 8px 0' }}>Cron Control Center encountered a UI error</h3>
          <p style={{ margin: '0 0 12px 0' }}>{this.state.error?.message || String(this.state.error)}</p>
          <button
            type="button"
            className="button button-primary"
            onClick={() => this.setState({ hasError: false, error: null })}
          >
            Recover View
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

function mountCronManager() {
  const container = document.getElementById('webcare-scanner-root') || document.getElementById('webcare-pro-root');
  if (!container) return;

  const app = (
    <CronManagerErrorBoundary>
      <WebCareShell activeTab="cron_manager">
        <CronManagerPage apiRequest={apiRequest} />
      </WebCareShell>
    </CronManagerErrorBoundary>
  );

  if (typeof createRoot === 'function') {
    createRoot(container).render(app);
  } else if (typeof render === 'function') {
    render(app, container);
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', mountCronManager);
} else {
  mountCronManager();
}
