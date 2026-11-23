import { Component, createRoot, render } from '@wordpress/element';
import '../utils/domPatch';
import { SetupWizard } from '../components/SetupWizard';
import { apiRequest } from '../utils/api';
import { AlertCircle, RefreshCw } from 'lucide-react';

interface ErrorBoundaryProps {
  children: any;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

class WizardErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: any) {
    console.error('[WebCare Setup Studio] Uncaught exception:', error, errorInfo);
  }

  handleReload = () => {
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      return (
        <div
          style={{
            maxWidth: '680px',
            margin: '40px auto',
            padding: '28px',
            background: 'var(--webcare-bg-panel, #ffffff)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            borderRadius: '16px',
            boxShadow: '0 10px 30px rgba(0,0,0,0.06)',
            color: 'var(--webcare-text-title, #0f172a)',
            fontFamily: 'system-ui, -apple-system, sans-serif',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '14px' }}>
            <div style={{ width: '40px', height: '40px', borderRadius: '10px', background: 'rgba(239, 68, 68, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#dc2626' }}>
              <AlertCircle size={22} />
            </div>
            <div>
              <h2 style={{ margin: 0, fontSize: '18px', fontWeight: 800 }}>Setup Studio Encountered a Render Interruption</h2>
              <p style={{ margin: '2px 0 0', fontSize: '13px', color: 'var(--webcare-text-secondary, #475569)' }}>
                Your progress is safely saved. Click below to refresh and resume the setup studio.
              </p>
            </div>
          </div>

          {this.state.error && (
            <pre
              style={{
                padding: '12px',
                background: 'var(--webcare-bg-elevated, #f8fafc)',
                border: '1px solid var(--webcare-border, #e2e8f0)',
                borderRadius: '8px',
                fontSize: '12px',
                color: '#dc2626',
                overflowX: 'auto',
                marginBottom: '18px',
              }}
            >
              {this.state.error.message}
            </pre>
          )}

          <div style={{ display: 'flex', gap: '12px' }}>
            <button
              type="button"
              onClick={this.handleReload}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                padding: '10px 20px',
                borderRadius: '8px',
                background: 'var(--webcare-primary, #4f46e5)',
                color: '#ffffff',
                border: 'none',
                fontSize: '13px',
                fontWeight: 700,
                cursor: 'pointer',
              }}
            >
              <RefreshCw size={15} /> Resume Setup Studio
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

function mountWizard() {
  const container = document.getElementById('webcare-scanner-root') || document.getElementById('webcare-pro-root');
  if (!container) return;

  const app = (
    <WizardErrorBoundary>
      <SetupWizard apiRequest={apiRequest} />
    </WizardErrorBoundary>
  );

  if (typeof createRoot === 'function') {
    createRoot(container).render(app);
  } else if (typeof render === 'function') {
    render(app, container);
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', mountWizard);
} else {
  mountWizard();
}
