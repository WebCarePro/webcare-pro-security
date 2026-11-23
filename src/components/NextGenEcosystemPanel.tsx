import React, { useEffect, useState } from '@wordpress/element';
import { Cpu, Shield, RefreshCw, Activity, CheckCircle2, XCircle, Layers } from 'lucide-react';
import { apiRequest } from '../utils/api';
import { WebCareSlot } from '../utils/moduleSlots';

interface EcosystemModuleItem {
  id: string;
  title: string;
  description: string;
  category: string;
  version: string;
  author: string;
  enable_key: string;
  enabled: boolean;
  applicable: boolean;
  is_waf: boolean;
  cron_count: number;
  route_count: number;
  mcp_count: number;
  deep_link: string;
  badge: string;
}

export const NextGenEcosystemPanel: React.FC = () => {
  const [modules, setModules] = useState<EcosystemModuleItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [togglingId, setTogglingId] = useState<string | null>(null);
  const [telemetry, setTelemetry] = useState<{
    intentCount: number;
    sqlRaspCount: number;
    deltaCount: number;
    checkoutAlerts: number;
    dlpCount: number;
  }>({ intentCount: 0, sqlRaspCount: 0, deltaCount: 0, checkoutAlerts: 0, dlpCount: 0 });

  const loadData = async () => {
    try {
      setLoading(true);
      const [ecoRes, icRes, sqlRes, deltaRes, chkRes, dlpRes] = await Promise.all([
        apiRequest({ path: '/modules/ecosystem' }).catch(() => null),
        apiRequest({ path: '/nextgen/intent-chains' }).catch(() => null),
        apiRequest({ path: '/nextgen/sql-rasp-events' }).catch(() => null),
        apiRequest({ path: '/nextgen/delta-reports' }).catch(() => null),
        apiRequest({ path: '/nextgen/checkout-skimmer' }).catch(() => null),
        apiRequest({ path: '/nextgen/dlp-events' }).catch(() => null),
      ]);
      if (ecoRes?.success && Array.isArray(ecoRes.modules)) {
        setModules(ecoRes.modules);
      }
      setTelemetry({
        intentCount: Array.isArray(icRes?.events) ? icRes.events.length : 0,
        sqlRaspCount: Array.isArray(sqlRes?.events) ? sqlRes.events.length : 0,
        deltaCount: Array.isArray(deltaRes?.reports) ? deltaRes.reports.length : 0,
        checkoutAlerts: Array.isArray(chkRes?.alerts) ? chkRes.alerts.length : 0,
        dlpCount: Array.isArray(dlpRes?.events) ? dlpRes.events.length : 0,
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleToggleModule = async (mod: EcosystemModuleItem) => {
    if (!mod.enable_key) return;
    try {
      setTogglingId(mod.id);
      const res = await apiRequest({
        path: '/modules/toggle',
        method: 'POST',
        data: { module_id: mod.id, enabled: !mod.enabled },
      });
      if (res?.success && Array.isArray(res.modules)) {
        setModules(res.modules);
      }
    } finally {
      setTogglingId(null);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      <div className="webcare-firewall-section-group" style={{ padding: '20px', borderRadius: '14px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px', marginBottom: '14px' }}>
          <div>
            <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Cpu size={17} style={{ color: 'var(--webcare-primary, #4f46e5)' }} />
              Pluggable Module SDK &amp; 2026–2027 Threat Defense Engines
            </h3>
            <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: 'var(--webcare-text-secondary, #475569)' }}>
              Unified Micro-Kernel Registry connecting autonomous AI-agent detection, guest SQL RASP, Delta AST scans, Checkout CSP, GraphQL shielding, and Response DLP.
            </p>
          </div>
          <button type="button" onClick={loadData} className="webcare-btn-micro" disabled={loading}>
            <RefreshCw size={13} /> Refresh Telemetry
          </button>
        </div>

        {/* Next-Gen Event Counters */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(175px, 1fr))', gap: '10px', marginBottom: '16px' }}>
          <div className="webcare-firewall-rule-card" style={{ padding: '12px', borderRadius: '10px' }}>
            <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)' }}>AI KILL-CHAIN EVENTS</div>
            <div style={{ fontSize: '20px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)' }}>{telemetry.intentCount}</div>
          </div>
          <div className="webcare-firewall-rule-card" style={{ padding: '12px', borderRadius: '10px' }}>
            <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)' }}>SQL RASP ABORTS</div>
            <div style={{ fontSize: '20px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)' }}>{telemetry.sqlRaspCount}</div>
          </div>
          <div className="webcare-firewall-rule-card" style={{ padding: '12px', borderRadius: '10px' }}>
            <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)' }}>DELTA UPGRADER SCANS</div>
            <div style={{ fontSize: '20px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)' }}>{telemetry.deltaCount}</div>
          </div>
          <div className="webcare-firewall-rule-card" style={{ padding: '12px', borderRadius: '10px' }}>
            <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)' }}>CHECKOUT SKIMMER ALERTS</div>
            <div style={{ fontSize: '20px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)' }}>{telemetry.checkoutAlerts}</div>
          </div>
          <div className="webcare-firewall-rule-card" style={{ padding: '12px', borderRadius: '10px' }}>
            <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)' }}>DLP SECRET BLOCKS</div>
            <div style={{ fontSize: '20px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)' }}>{telemetry.dlpCount}</div>
          </div>
        </div>

        {/* Registered Module Cards */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(310px, 1fr))', gap: '12px' }}>
          {modules.map((mod) => (
            <div key={mod.id} className="webcare-firewall-rule-card" style={{ padding: '16px', borderRadius: '12px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between', gap: '10px' }}>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '8px' }}>
                  <strong style={{ fontSize: '14px', color: 'var(--webcare-text-title, #0f172a)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    {mod.is_waf ? <Shield size={15} style={{ color: 'var(--webcare-primary, #4f46e5)' }} /> : <Layers size={15} style={{ color: '#0284c7' }} />}
                    {mod.title}
                  </strong>
                  {mod.badge && <span className="webcare-badge-pill webcare-badge-info">{mod.badge}</span>}
                </div>
                <p style={{ margin: '6px 0 0 0', fontSize: '12px', lineHeight: 1.45, color: 'var(--webcare-text-secondary, #475569)' }}>
                  {mod.description}
                </p>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: '8px', borderTop: '1px solid var(--webcare-border, #e2e8f0)', fontSize: '11px' }}>
                <span style={{ color: 'var(--webcare-text-muted, #64748b)' }}>
                  <Activity size={11} style={{ verticalAlign: 'middle', marginRight: '3px' }} />
                  {mod.route_count} REST &bull; {mod.cron_count} Cron &bull; {mod.mcp_count} MCP
                </span>

                {mod.enable_key ? (
                  <button
                    type="button"
                    disabled={togglingId === mod.id}
                    onClick={() => handleToggleModule(mod)}
                    className={`webcare-firewall-rule-save-btn ${mod.enabled ? 'is-saved' : ''}`}
                    style={{ display: 'inline-flex', alignItems: 'center', gap: '5px', padding: '5px 11px', fontSize: '11px' }}
                  >
                    {mod.enabled ? <CheckCircle2 size={12} /> : <XCircle size={12} />}
                    {mod.enabled ? 'Enabled' : 'Disabled'}
                  </button>
                ) : (
                  <span className="webcare-badge-pill webcare-badge-success">Core Active</span>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Third-Party Extension React Slot */}
      <WebCareSlot name="modular_waf.nextgen_cards" context={{ modules, telemetry }} />
    </div>
  );
};
