import React, { useState, useEffect } from '@wordpress/element';
import { WafLogsPage } from './WafLogsPage';
import { ActivityLogsPage } from './ActivityLogs/ActivityLogsPage';
import { ScanLogsPage } from './ScanLogsPage';
import { ShieldAlert, Activity, History } from 'lucide-react';
import { buildAdminUrl, navigateToRoute, parseCurrentRoute, updateDocumentTitle } from './utils/routeRegistry';

interface LogsAndActivityUnifiedPageProps {
  apiRequest: (options: { path: string; method?: string; data?: any }) => Promise<any>;
}

export const LogsAndActivityUnifiedPage: React.FC<LogsAndActivityUnifiedPageProps> = ({ apiRequest }) => {
  const [activeTab, setActiveTab] = useState<'firewall' | 'activity' | 'scans'>(() => {
    const route = parseCurrentRoute();
    if (route.tab === 'activity') return 'activity';
    if (route.tab === 'scans' || route.tab === 'scan_logs') return 'scans';
    return 'firewall';
  });

  useEffect(() => {
    const handleSync = () => {
      const route = parseCurrentRoute();
      if (route.tab === 'activity') setActiveTab('activity');
      else if (route.tab === 'scans' || route.tab === 'scan_logs') setActiveTab('scans');
      else setActiveTab('firewall');
    };
    window.addEventListener('popstate', handleSync);
    window.addEventListener('webcare:route-change', handleSync);
    return () => {
      window.removeEventListener('popstate', handleSync);
      window.removeEventListener('webcare:route-change', handleSync);
    };
  }, []);

  const handleTabSwitch = (tab: 'firewall' | 'activity' | 'scans') => {
    setActiveTab(tab);
    navigateToRoute('webcare-pro-logs', tab, '', {}, { onTabChange: (t) => {} });
  };

  return (
    <div className="webcare-unified-logs-page" style={{ padding: '0 0 24px 0' }}>
      {/* Pillar Header Sub-Navigation Bar */}
      <div 
        className="webcare-subnav-bar"
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '12px 20px',
          background: 'var(--webcare-bg-surface, #ffffff)',
          borderBottom: '1px solid var(--webcare-border, #e2e8f0)',
          marginBottom: '20px'
        }}
      >
        <button
          type="button"
          onClick={() => handleTabSwitch('firewall')}
          className={`webcare-tab-pill ${activeTab === 'firewall' ? 'is-active' : ''}`}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            padding: '8px 16px',
            borderRadius: '8px',
            fontSize: '13px',
            fontWeight: 600,
            cursor: 'pointer',
            border: activeTab === 'firewall' ? '1px solid #4f46e5' : '1px solid var(--webcare-border, #cbd5e1)',
            background: activeTab === 'firewall' ? 'linear-gradient(135deg, #4f46e5 0%, #4338ca 100%)' : 'var(--webcare-bg-surface, #f8fafc)',
            color: activeTab === 'firewall' ? '#ffffff' : 'var(--webcare-text-secondary, #475569)',
            transition: 'all 0.15s ease',
          }}
        >
          <ShieldAlert size={14} />
          <span>Blocked Traffic &amp; Bans</span>
        </button>

        <button
          type="button"
          onClick={() => handleTabSwitch('activity')}
          className={`webcare-tab-pill ${activeTab === 'activity' ? 'is-active' : ''}`}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            padding: '8px 16px',
            borderRadius: '8px',
            fontSize: '13px',
            fontWeight: 600,
            cursor: 'pointer',
            border: activeTab === 'activity' ? '1px solid #4f46e5' : '1px solid var(--webcare-border, #cbd5e1)',
            background: activeTab === 'activity' ? 'linear-gradient(135deg, #4f46e5 0%, #4338ca 100%)' : 'var(--webcare-bg-surface, #f8fafc)',
            color: activeTab === 'activity' ? '#ffffff' : 'var(--webcare-text-secondary, #475569)',
            transition: 'all 0.15s ease',
          }}
        >
          <Activity size={14} />
          <span>Admin Activity</span>
        </button>

        <button
          type="button"
          onClick={() => handleTabSwitch('scans')}
          className={`webcare-tab-pill ${activeTab === 'scans' ? 'is-active' : ''}`}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            padding: '8px 16px',
            borderRadius: '8px',
            fontSize: '13px',
            fontWeight: 600,
            cursor: 'pointer',
            border: activeTab === 'scans' ? '1px solid #4f46e5' : '1px solid var(--webcare-border, #cbd5e1)',
            background: activeTab === 'scans' ? 'linear-gradient(135deg, #4f46e5 0%, #4338ca 100%)' : 'var(--webcare-bg-surface, #f8fafc)',
            color: activeTab === 'scans' ? '#ffffff' : 'var(--webcare-text-secondary, #475569)',
            transition: 'all 0.15s ease',
          }}
        >
          <History size={14} />
          <span>Scan History</span>
        </button>
      </div>

      {/* Tab Panels */}
      <div className="webcare-tab-content-wrapper" style={{ padding: '0 20px' }}>
        {activeTab === 'firewall' && (
          <WafLogsPage
            apiRequest={apiRequest}
            onNavigateToFirewallRules={() => navigateToRoute('webcare-pro-firewall', 'protection')}
            onNavigateToDashboard={() => navigateToRoute('webcare-pro-security')}
            onNavigateToFirewall={(sub) => navigateToRoute('webcare-pro-firewall', sub || 'protection')}
          />
        )}

        {activeTab === 'activity' && (
          <ActivityLogsPage apiRequest={apiRequest} />
        )}

        {activeTab === 'scans' && (
          <ScanLogsPage
            apiRequest={apiRequest}
            onNavigateToScanner={() => navigateToRoute('webcare-pro-scanner', 'malware')}
          />
        )}
      </div>
    </div>
  );
};

export default LogsAndActivityUnifiedPage;
