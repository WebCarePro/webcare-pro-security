import { useState, useEffect } from '@wordpress/element';
import { CheckCircle2, AlertTriangle, AlertCircle, Info, X } from 'lucide-react';

export type ToastType = 'success' | 'error' | 'warning' | 'info';

export interface ToastItem {
  id: string;
  type: ToastType;
  message: string;
  duration?: number;
}

type ToastListener = (toast: ToastItem) => void;

class ToastEventManager {
  private listeners: ToastListener[] = [];

  subscribe(listener: ToastListener): () => void {
    this.listeners.push(listener);
    return () => {
      this.listeners = this.listeners.filter((l) => l !== listener);
    };
  }

  emit(toast: ToastItem): void {
    this.listeners.forEach((listener) => {
      try {
        listener(toast);
      } catch (err) {
        console.error('Toast listener error:', err);
      }
    });
  }
}

const toastEventBus = new ToastEventManager();

export const toast = {
  success: (message: string, duration = 4000) => {
    toastEventBus.emit({
      id: `toast-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      type: 'success',
      message,
      duration,
    });
  },
  error: (message: string, duration = 5000) => {
    toastEventBus.emit({
      id: `toast-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      type: 'error',
      message,
      duration,
    });
  },
  warning: (message: string, duration = 4500) => {
    toastEventBus.emit({
      id: `toast-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      type: 'warning',
      message,
      duration,
    });
  },
  info: (message: string, duration = 4000) => {
    toastEventBus.emit({
      id: `toast-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      type: 'info',
      message,
      duration,
    });
  },
};

// Also expose globally for legacy callbacks if needed
if (typeof window !== 'undefined') {
  (window as any).webcareToast = toast;
}

interface ToastCardProps {
  toast: ToastItem;
  onDismiss: (id: string) => void;
}

const ToastCard = ({ toast: item, onDismiss }: ToastCardProps) => {
  const [isPaused, setIsPaused] = useState(false);

  useEffect(() => {
    if (isPaused || (item.duration && item.duration <= 0)) return;

    const timer = setTimeout(() => {
      onDismiss(item.id);
    }, item.duration ?? 4000);

    return () => clearTimeout(timer);
  }, [item.id, item.duration, isPaused, onDismiss]);

  const getThemeStyles = () => {
    switch (item.type) {
      case 'success':
        return {
          icon: <CheckCircle2 size={18} style={{ color: '#10b981', flexShrink: 0 }} />,
          borderLeft: '4px solid #10b981',
          bg: 'var(--webcare-bg-panel, #ffffff)',
          text: 'var(--webcare-text-primary, #0f172a)',
        };
      case 'error':
        return {
          icon: <AlertCircle size={18} style={{ color: '#ef4444', flexShrink: 0 }} />,
          borderLeft: '4px solid #ef4444',
          bg: 'var(--webcare-bg-panel, #ffffff)',
          text: 'var(--webcare-text-primary, #0f172a)',
        };
      case 'warning':
        return {
          icon: <AlertTriangle size={18} style={{ color: '#f59e0b', flexShrink: 0 }} />,
          borderLeft: '4px solid #f59e0b',
          bg: 'var(--webcare-bg-panel, #ffffff)',
          text: 'var(--webcare-text-primary, #0f172a)',
        };
      case 'info':
      default:
        return {
          icon: <Info size={18} style={{ color: '#3b82f6', flexShrink: 0 }} />,
          borderLeft: '4px solid #3b82f6',
          bg: 'var(--webcare-bg-panel, #ffffff)',
          text: 'var(--webcare-text-primary, #0f172a)',
        };
    }
  };

  const theme = getThemeStyles();

  return (
    <div
      role="status"
      aria-live="polite"
      className="webcare-toast-card"
      onMouseEnter={() => setIsPaused(true)}
      onMouseLeave={() => setIsPaused(false)}
      style={{
        display: 'flex',
        alignItems: 'flex-start',
        gap: '10px',
        padding: '12px 14px',
        borderRadius: '10px',
        background: theme.bg,
        border: '1px solid var(--webcare-border, #e2e8f0)',
        borderLeft: theme.borderLeft,
        boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.15), 0 8px 10px -6px rgba(0, 0, 0, 0.1)',
        color: theme.text,
        fontSize: '13px',
        lineHeight: '1.45',
        fontWeight: 500,
        minWidth: '280px',
        maxWidth: '420px',
        pointerEvents: 'auto',
        animation: 'webcare-toast-slide-in 0.25s ease-out forwards',
        wordBreak: 'break-word',
      }}
    >
      <div style={{ marginTop: '2px' }}>{theme.icon}</div>
      <div style={{ flex: 1 }}>{item.message}</div>
      <button
        type="button"
        onClick={() => onDismiss(item.id)}
        aria-label="Dismiss notification"
        style={{
          background: 'none',
          border: 'none',
          cursor: 'pointer',
          padding: '2px',
          color: 'var(--webcare-text-muted, #94a3b8)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          borderRadius: '4px',
          marginLeft: '4px',
          transition: 'color 0.15s ease',
        }}
        onMouseEnter={(e) => {
          (e.currentTarget as HTMLElement).style.color = 'var(--webcare-text-primary, #0f172a)';
        }}
        onMouseLeave={(e) => {
          (e.currentTarget as HTMLElement).style.color = 'var(--webcare-text-muted, #94a3b8)';
        }}
      >
        <X size={15} />
      </button>
    </div>
  );
};

export const ToastProvider = () => {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  useEffect(() => {
    const unsubscribe = toastEventBus.subscribe((newToast) => {
      setToasts((prev) => [...prev, newToast]);
    });
    return unsubscribe;
  }, []);

  const handleDismiss = (id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  };

  return (
    <div
      aria-live="polite"
      aria-atomic="false"
      style={{
        position: 'fixed',
        top: '48px',
        right: '24px',
        zIndex: 999999,
        display: 'flex',
        flexDirection: 'column',
        gap: '8px',
        pointerEvents: 'none',
        maxWidth: '100%',
      }}
    >
      {toasts.map((item) => (
        <ToastCard key={item.id} toast={item} onDismiss={handleDismiss} />
      ))}
    </div>
  );
};

export default ToastProvider;
