import React, { useEffect, useState } from 'react';
import { Radar, Save, CheckCircle2 } from 'lucide-react';

interface PublicThreatIntelSettingsCardProps {
  apiRequest: (options: { path: string; method?: string; data?: any }) => Promise<any>;
}

export const PublicThreatIntelSettingsCard: React.FC<PublicThreatIntelSettingsCardProps> = ({ apiRequest }) => {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [savedNotice, setSavedNotice] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [prefs, setPrefs] = useState({
    threat_intel_enabled: true,
    threat_intel_cisa_kev_enabled: true,
    threat_intel_nvd_cve_enabled: true,
    threat_intel_public_cidr_enabled: true,
  });

  useEffect(() => {
    let mounted = true;
    (async () => {
      try {
        const res = await apiRequest({ path: '/settings', method: 'GET' });
        const s = res?.settings || res || {};
        if (mounted) {
          setPrefs({
            threat_intel_enabled: s.threat_intel_enabled !== false,
            threat_intel_cisa_kev_enabled: s.threat_intel_cisa_kev_enabled !== false,
            threat_intel_nvd_cve_enabled: s.threat_intel_nvd_cve_enabled !== false,
            threat_intel_public_cidr_enabled: s.threat_intel_public_cidr_enabled !== false,
          });
        }
      } catch {
        // Keep safe defaults
      } finally {
        if (mounted) setLoading(false);
      }
    })();
    return () => {
      mounted = false;
    };
  }, [apiRequest]);

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    setSavedNotice(false);
    try {
      await apiRequest({
        path: '/settings',
        method: 'POST',
        data: prefs,
      });
      setSavedNotice(true);
      setTimeout(() => setSavedNotice(false), 3000);
    } catch (err: any) {
      setError(err?.message || 'Unable to save threat feed preferences.');
    } finally {
      setSaving(false);
    }
  };

  const rows: Array<{
    key: keyof typeof prefs;
    label: string;
    desc: string;
    badge: string;
    indented?: boolean;
  }> = [
    {
      key: 'threat_intel_enabled',
      label: 'Master Threat Intelligence Synchronization',
      desc: 'Enables automated background synchronization of free, public vulnerability catalogs and malicious network feeds.',
      badge: prefs.threat_intel_enabled ? 'Active' : 'Disabled',
    },
    {
      key: 'threat_intel_cisa_kev_enabled',
      label: 'CISA Known Exploited Vulnerabilities (KEV)',
      desc: "Fetches CISA's official catalog of actively exploited in-the-wild zero-days with ETag and Last-Modified caching headers.",
      badge: prefs.threat_intel_cisa_kev_enabled ? 'CISA Active' : 'Off',
      indented: true,
    },
    {
      key: 'threat_intel_nvd_cve_enabled',
      label: 'NVD CVE 2.0 (Incremental WordPress Delta)',
      desc: 'Pulls official WordPress CVE advisories directly from NIST NVD 2.0 without sending any local plugin information.',
      badge: prefs.threat_intel_nvd_cve_enabled ? 'NVD Active' : 'Off',
      indented: true,
    },
    {
      key: 'threat_intel_public_cidr_enabled',
      label: 'Public Malicious Botnet & Scanner CIDRs (Spamhaus DROP / FireHOL)',
      desc: 'Pulls verified high-confidence drop lists and network blocksets to preemptively stop brute-force attacks and automated scanners.',
      badge: prefs.threat_intel_public_cidr_enabled ? 'CIDRs Active' : 'Off',
      indented: true,
    },
  ];

  return (
    <div
      className="webcare-firewall-section-group"
      style={{
        marginBottom: '20px',
        padding: '22px',
        borderRadius: '14px',
        border: '1px solid var(--webcare-border, #e2e8f0)',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '16px', flexWrap: 'wrap', marginBottom: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{ background: 'rgba(8, 145, 178, 0.12)', color: '#0891b2', padding: '10px', borderRadius: '10px', display: 'flex' }}>
            <Radar size={20} />
          </div>
          <div>
            <h3 style={{ margin: 0, fontSize: '16.5px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
              Public Threat Intelligence Feeds
            </h3>
            <p style={{ margin: '2px 0 0', fontSize: '13px', color: 'var(--webcare-text-secondary, #475569)' }}>
              Pull-only public feeds — zero site data, plugin lists, or visitor IPs ever leave your server.
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          {savedNotice && (
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '5px', fontSize: '12.5px', fontWeight: 600, color: '#059669' }}>
              <CheckCircle2 size={15} /> Saved
            </span>
          )}
          <button
            type="button"
            onClick={handleSave}
            disabled={saving || loading}
            className="button button-primary"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '7px',
              padding: '7px 14px',
              borderRadius: '8px',
              fontWeight: 600,
              background: '#4f46e5',
              borderColor: '#4338ca',
            }}
          >
            <Save size={14} />
            <span>{saving ? 'Saving...' : 'Save Feed Settings'}</span>
          </button>
        </div>
      </div>

      {error && (
        <div style={{ marginBottom: '12px', padding: '10px 12px', borderRadius: '8px', background: '#fef2f2', border: '1px solid #fecaca', color: '#dc2626', fontSize: '13px' }}>
          {error}
        </div>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
        {rows.map((row) => (
          <label
            key={row.key}
            className="webcare-firewall-rule-card"
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              justifyContent: 'space-between',
              gap: '14px',
              padding: '14px 16px',
              borderRadius: '10px',
              border: '1px solid var(--webcare-border, #e2e8f0)',
              marginLeft: row.indented ? '16px' : '0',
              cursor: 'pointer',
              opacity: row.indented && !prefs.threat_intel_enabled ? 0.55 : 1,
            }}
          >
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                <span style={{ fontSize: '13.5px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                  {row.label}
                </span>
                <span className="webcare-firewall-role-chip" style={{ fontSize: '11px', fontWeight: 600 }}>
                  {row.badge}
                </span>
              </div>
              <p style={{ margin: '4px 0 0', fontSize: '12.5px', lineHeight: 1.5, color: 'var(--webcare-text-secondary, #475569)' }}>
                {row.desc}
              </p>
            </div>
            <input
              type="checkbox"
              checked={prefs[row.key]}
              disabled={loading || (row.indented && !prefs.threat_intel_enabled)}
              onChange={(e) => setPrefs((prev) => ({ ...prev, [row.key]: e.target.checked }))}
              style={{ marginTop: '3px', width: '18px', height: '18px', accentColor: '#4f46e5', cursor: 'pointer' }}
            />
          </label>
        ))}
      </div>
    </div>
  );
};
