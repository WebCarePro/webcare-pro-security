import { Component, createRoot, render } from '@wordpress/element';
import './utils/domPatch';
import App from './App';
import ToastProvider from './components/ui/ToastProvider';
import ConfirmModalHost from './components/ui/ConfirmModal';

interface ErrorBoundaryProps {
  children: any;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}


class RootErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: any) {
    console.error('WebCare Pro Security & Firewall Error Boundary caught:', error, errorInfo);
    (window as any).webcareLastBoundaryError = {
      message: error.message,
      stack: error.stack,
      componentStack: errorInfo?.componentStack
    };
  }

  handleReload = () => {
    this.setState({ hasError: false, error: null });
    window.location.reload();
  };

  handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

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
          boxShadow: '0 4px 12px rgba(0, 0, 0, 0.05)',
          fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
            <span style={{ fontSize: '20px' }}>⚠️</span>
            <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: '#991b1b' }}>
              WebCare Pro Security & Firewall UI Encountered an Issue
            </h3>
          </div>
          <p style={{ margin: '0 0 16px 0', fontSize: '13px', color: '#475569', lineHeight: 1.5 }}>
            An unexpected error occurred during rendering or scan state transition. Click below to recover and resume your session cleanly.
          </p>
          {this.state.error && (
            <div style={{
              background: '#f8fafc',
              border: '1px solid #e2e8f0',
              borderRadius: '8px',
              padding: '10px 14px',
              fontSize: '12px',
              color: '#64748b',
              fontFamily: 'monospace',
              marginBottom: '16px',
              overflowX: 'auto'
            }}>
              {this.state.error.message || String(this.state.error)}
            </div>
          )}
          <div style={{ display: 'flex', gap: '10px' }}>
            <button
              type="button"
              onClick={this.handleReset}
              style={{
                background: '#4f46e5',
                color: '#ffffff',
                border: 'none',
                borderRadius: '8px',
                padding: '8px 16px',
                fontSize: '13px',
                fontWeight: 600,
                cursor: 'pointer'
              }}
            >
              Recover View
            </button>
            <button
              type="button"
              onClick={this.handleReload}
              style={{
                background: '#f1f5f9',
                color: '#334155',
                border: '1px solid #cbd5e1',
                borderRadius: '8px',
                padding: '8px 16px',
                fontSize: '13px',
                fontWeight: 600,
                cursor: 'pointer'
              }}
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

function initApp() {
  const container = document.getElementById('webcare-scanner-root') || document.getElementById('webcare-pro-root');
  if (!container) {
    return;
  }

  try {
    const wrappedElement = (
      <RootErrorBoundary>
        <App />
        <ToastProvider />
        <ConfirmModalHost />
      </RootErrorBoundary>
    );

    if (typeof createRoot === 'function') {
      const root = createRoot(container);
      root.render(wrappedElement);
    } else if (typeof render === 'function') {
      render(wrappedElement, container);
    }
  } catch (err) {
    console.error('WebCare Pro Security & Firewall Mount Error:', err);
    container.innerHTML = '<div style="padding: 20px; color: red;">Failed to load WebCare Pro dashboard. Check browser console for details.</div>';
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initApp);
} else {
  initApp();
}

