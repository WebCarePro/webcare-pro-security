import React from 'react';
import {
  ShieldAlert,
  Zap,
  Sliders,
  History,
  Activity,
  ArrowLeft,
  Sparkles,
  ShieldCheck
} from 'lucide-react';
import { VirtualPatchCard } from './components/VirtualPatchCard';

interface VirtualPatchPageProps {
  apiRequest: (options: { path: string; method?: string; data?: any }) => Promise<any>;
  onNavigateToFirewall?: (subTab?: string) => void;
  onNavigateToWafLogs?: () => void;
  onNavigateToDashboard?: () => void;
}

export const VirtualPatchPage: React.FC<VirtualPatchPageProps> = ({
  apiRequest,
  onNavigateToFirewall,
  onNavigateToWafLogs,
  onNavigateToDashboard,
}) => {
  return (
    <div className="webcare-page-container" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Top Header Card */}
      <div className="webcare-card" style={{ padding: '24px 28px', borderRadius: '14px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
              <button
                type="button"
                className="webcare-btn-secondary"
                onClick={() => onNavigateToFirewall ? onNavigateToFirewall('rules') : (window.location.href = 'admin.php?page=webcare-pro-firewall')}
                style={{
                  fontSize: '12px',
                  padding: '4px 10px',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '5px',
                  borderRadius: '6px'
                }}
              >
                <ArrowLeft size={13} />
                <span>Back to Firewall &amp; WAF</span>
              </button>
              <span className="webcare-badge-neutral" style={{ fontSize: '11px', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                <Zap size={11} color="#f59e0b" />
                <span>Autonomous Hotpatch Studio</span>
              </span>
              <span className="webcare-badge-clean" style={{ fontSize: '11px', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                <ShieldCheck size={11} color="#10b981" />
                <span>Dual-Layer In-Memory Simulation</span>
              </span>
            </div>

            <h2 style={{
              margin: '0 0 6px 0',
              fontSize: '22px',
              fontWeight: 800,
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              color: 'var(--webcare-text-primary)'
            }}>
              <ShieldAlert size={24} color="#ea580c" />
              <span>Virtual Patching &amp; 0-Day Exploit Studio</span>
            </h2>

            <p style={{ margin: 0, fontSize: '13px', color: 'var(--webcare-text-secondary)', maxWidth: '850px', lineHeight: 1.5 }}>
              Synthesize zero-day micro-rules, run sub-microsecond in-memory synthetic payload benchmarks, and deploy instantaneous virtual patches before official CVE vendor updates are released.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
            <button
              type="button"
              className="webcare-btn-secondary"
              onClick={() => onNavigateToFirewall ? onNavigateToFirewall('rules') : (window.location.href = 'admin.php?page=webcare-pro-firewall&tab=waf-rules')}
              style={{ fontSize: '12.5px', padding: '8px 14px', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
            >
              <Sliders size={14} />
              <span>Firewall Rules</span>
            </button>
            <button
              type="button"
              className="webcare-btn-secondary"
              onClick={() => onNavigateToWafLogs ? onNavigateToWafLogs() : (window.location.href = 'admin.php?page=webcare-pro-logs&tab=firewall')}
              style={{ fontSize: '12.5px', padding: '8px 14px', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
            >
              <History size={14} />
              <span>WAF Incident Logs &rarr;</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Virtual Patch Card */}
      <VirtualPatchCard
        apiRequest={apiRequest}
        onNavigateToSettings={() => onNavigateToFirewall ? onNavigateToFirewall('cloudflare') : (window.location.href = 'admin.php?page=webcare-pro-firewall&tab=cloudflare')}
      />
    </div>
  );
};

export default VirtualPatchPage;
