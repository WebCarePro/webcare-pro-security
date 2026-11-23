import React, { useState } from 'react';
import {
  Server,
  Shield,
  FileCode,
  CheckCircle2,
  AlertCircle,
  Copy,
  Check,
  Loader2,
  Sliders,
  Lock,
  Globe
} from 'lucide-react';
import { DeveloperDeepDive } from '../DeveloperDeepDive';
import { apiRequest } from '../../../utils/api';

interface Step10Props {
  serverSettings: {
    htaccess_hardening_enabled: boolean;
    disable_file_editing: boolean;
    security_headers_enabled: boolean;
    hsts_enabled: boolean;
    x_frame_options: string;
    referrer_policy: string;
  };
  setServerSettings: React.Dispatch<React.SetStateAction<any>>;
}

export const Step10ServerArmorHeaders: React.FC<Step10Props> = ({
  serverSettings,
  setServerSettings,
}) => {
  const [deployingArmor, setDeployingArmor] = useState(false);
  const [deployResult, setDeployResult] = useState<{ success: boolean; message: string } | null>(null);
  const [copiedNginx, setCopiedNginx] = useState(false);

  const handleDeployHtaccess = async () => {
    setDeployingArmor(true);
    setDeployResult(null);
    try {
      const res = await apiRequest({
        path: '/firewall/server-security/deploy-htaccess',
        method: 'POST'
      });
      if (res && res.success) {
        setDeployResult({
          success: true,
          message: res.message || 'Server Armor .htaccess directives written and verified successfully!'
        });
      } else {
        setDeployResult({
          success: false,
          message: res?.message || 'Could not deploy .htaccess rules automatically. Check filesystem permissions.'
        });
      }
    } catch (e: any) {
      setDeployResult({
        success: false,
        message: e?.message || 'Failed to trigger Server Armor deployment.'
      });
    } finally {
      setDeployingArmor(false);
    }
  };

  const nginxSnippet = `# WebCare Pro Server Armor Rules for Nginx
location ~* /(?:uploads|files)/.*\\.php$ {
    deny all;
}
location ~* /(?:wp-config\\.php|\\.htaccess|\\.user\\.ini|error_log|debug\\.log) {
    deny all;
}
autoindex off;`;

  const handleCopyNginx = () => {
    navigator.clipboard.writeText(nginxSnippet);
    setCopiedNginx(true);
    setTimeout(() => setCopiedNginx(false), 2000);
  };

  return (
    <div className="webcare-wizard-step-container" style={{ display: 'flex', flexDirection: 'column', gap: '24px', width: '100%', minWidth: 0, boxSizing: 'border-box' }}>
      {/* Step Header */}
      <div>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '4px 10px', borderRadius: '20px', background: 'var(--webcare-primary-soft, rgba(79, 70, 229, 0.08))', color: 'var(--webcare-primary, #4f46e5)', fontSize: '12px', fontWeight: 700, marginBottom: '12px' }}>
          <Server size={14} /> Phase 3: Identity &amp; OS Hardening
        </div>
        <h1 style={{ margin: '0 0 10px 0', fontSize: '24px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)' }}>
          Server Armor &amp; HTTP Security Headers
        </h1>
        <p style={{ fontSize: '14px', lineHeight: 1.6, color: 'var(--webcare-text-secondary, #475569)', margin: 0 }}>
          Harden web server configuration files to disable PHP execution in media uploads directories and enforce modern browser security headers.
        </p>
      </div>

      {/* Filesystem Server Armor Card */}
      <div style={{ padding: '20px', borderRadius: '12px', background: 'var(--webcare-bg-panel, #ffffff)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', flexWrap: 'wrap', gap: '10px' }}>
          <div>
            <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
              1-Click Server Armor (.htaccess / Apache / LiteSpeed)
            </div>
            <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px' }}>
              Blocks uploaded webshell execution and locks down sensitive server configuration files.
            </div>
          </div>
          <button
            type="button"
            onClick={handleDeployHtaccess}
            disabled={deployingArmor}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 16px',
              borderRadius: '8px',
              fontSize: '12px',
              fontWeight: 700,
              cursor: 'pointer',
              background: 'var(--webcare-primary, #4f46e5)',
              color: '#ffffff',
              border: 'none',
              opacity: deployingArmor ? 0.7 : 1
            }}
          >
            {deployingArmor ? <Loader2 size={14} className="webcare-spin" /> : <Shield size={14} />}
            Deploy Server Armor Rules
          </button>
        </div>

        {deployResult && (
          <div style={{ marginBottom: '14px', padding: '10px 14px', borderRadius: '8px', background: deployResult.success ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)', border: `1px solid ${deployResult.success ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`, display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', color: deployResult.success ? '#059669' : '#dc2626' }}>
            {deployResult.success ? <CheckCircle2 size={16} /> : <AlertCircle size={16} />}
            {deployResult.message}
          </div>
        )}

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '12px' }}>
          <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', padding: '12px', borderRadius: '8px', background: 'var(--webcare-bg-elevated, #f8fafc)', border: '1px solid var(--webcare-border, #e2e8f0)', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={serverSettings.htaccess_hardening_enabled}
              onChange={(e) => setServerSettings((prev: any) => ({ ...prev, htaccess_hardening_enabled: e.target.checked }))}
              style={{ marginTop: '2px', accentColor: 'var(--webcare-primary, #4f46e5)' }}
            />
            <div>
              <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                Block PHP in Uploads Directory
              </div>
              <div style={{ fontSize: '11px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px' }}>
                Prevents backdoor scripts in <code>/wp-content/uploads/</code> from executing.
              </div>
            </div>
          </label>

          <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', padding: '12px', borderRadius: '8px', background: 'var(--webcare-bg-elevated, #f8fafc)', border: '1px solid var(--webcare-border, #e2e8f0)', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={serverSettings.disable_file_editing}
              onChange={(e) => setServerSettings((prev: any) => ({ ...prev, disable_file_editing: e.target.checked }))}
              style={{ marginTop: '2px', accentColor: 'var(--webcare-primary, #4f46e5)' }}
            />
            <div>
              <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                Disable Theme &amp; Plugin File Editor
              </div>
              <div style={{ fontSize: '11px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px' }}>
                Defines <code>DISALLOW_FILE_EDIT</code> to stop attackers from modifying code via wp-admin.
              </div>
            </div>
          </label>
        </div>
      </div>

      {/* HTTP Security Headers Suite */}
      <div style={{ padding: '20px', borderRadius: '12px', background: 'var(--webcare-bg-elevated, #f8fafc)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
          <div>
            <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
              HTTP Security Headers Suite
            </div>
            <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px' }}>
              Instructs visitor browsers to enforce strict MIME sniffing and framing policies.
            </div>
          </div>
          <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={serverSettings.security_headers_enabled}
              onChange={(e) => setServerSettings((prev: any) => ({ ...prev, security_headers_enabled: e.target.checked }))}
              style={{ accentColor: 'var(--webcare-primary, #4f46e5)' }}
            />
            <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
              Enable Security Headers
            </span>
          </label>
        </div>

        {serverSettings.security_headers_enabled && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '12px' }}>
            <div style={{ padding: '12px', borderRadius: '8px', background: 'var(--webcare-bg-panel, #ffffff)', border: '1px solid var(--webcare-border, #cbd5e1)', fontSize: '12px' }}>
              <div style={{ fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>X-Content-Type-Options: nosniff</div>
              <div style={{ color: 'var(--webcare-text-secondary, #475569)', fontSize: '11px', marginTop: '2px' }}>
                Prevents browser MIME-type sniffing exploits.
              </div>
            </div>

            <div style={{ padding: '12px', borderRadius: '8px', background: 'var(--webcare-bg-panel, #ffffff)', border: '1px solid var(--webcare-border, #cbd5e1)', fontSize: '12px' }}>
              <div style={{ fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>X-Frame-Options: SAMEORIGIN</div>
              <div style={{ color: 'var(--webcare-text-secondary, #475569)', fontSize: '11px', marginTop: '2px' }}>
                Guards against iframe clickjacking attacks.
              </div>
            </div>

            <div style={{ padding: '12px', borderRadius: '8px', background: 'var(--webcare-bg-panel, #ffffff)', border: '1px solid var(--webcare-border, #cbd5e1)', fontSize: '12px' }}>
              <div style={{ fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>Referrer-Policy: strict-origin</div>
              <div style={{ color: 'var(--webcare-text-secondary, #475569)', fontSize: '11px', marginTop: '2px' }}>
                Protects sensitive checkout parameters in referer headers.
              </div>
            </div>

            <label style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', padding: '12px', borderRadius: '8px', background: 'var(--webcare-bg-panel, #ffffff)', border: '1px solid var(--webcare-border, #cbd5e1)', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={serverSettings.hsts_enabled}
                onChange={(e) => setServerSettings((prev: any) => ({ ...prev, hsts_enabled: e.target.checked }))}
                style={{ marginTop: '2px', accentColor: 'var(--webcare-primary, #4f46e5)' }}
              />
              <div>
                <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                  Strict-Transport-Security (HSTS)
                </div>
                <div style={{ fontSize: '11px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px' }}>
                  Forces 100% HTTPS traffic for 1 year (only enable if SSL is active).
                </div>
              </div>
            </label>
          </div>
        )}
      </div>

      {/* Developer Deep Dive: Nginx Snippet */}
      <DeveloperDeepDive
        title="Developer Controls: Nginx Configuration Rules"
        badge="nginx.conf snippet"
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)' }}>
              If your host runs pure Nginx without Apache/LiteSpeed <code>.htaccess</code> emulation, paste this into your server block:
            </span>
            <button
              type="button"
              onClick={handleCopyNginx}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '4px',
                fontSize: '11px',
                fontWeight: 600,
                color: copiedNginx ? '#059669' : 'var(--webcare-primary, #4f46e5)',
                background: 'none',
                border: 'none',
                cursor: 'pointer'
              }}
            >
              {copiedNginx ? <Check size={12} /> : <Copy size={12} />}
              {copiedNginx ? 'Copied' : 'Copy Nginx Rules'}
            </button>
          </div>
          <pre
            style={{
              padding: '12px',
              borderRadius: '8px',
              background: 'var(--webcare-bg-deep, #090d16)',
              color: '#38bdf8',
              fontSize: '11px',
              fontFamily: 'monospace',
              overflowX: 'auto',
              margin: 0
            }}
          >
            {nginxSnippet}
          </pre>
        </div>
      </DeveloperDeepDive>
    </div>
  );
};
