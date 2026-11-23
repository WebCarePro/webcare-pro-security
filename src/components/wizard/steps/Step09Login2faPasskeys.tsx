import React from 'react';
import { Lock } from 'lucide-react';
import { DeveloperDeepDive } from '../DeveloperDeepDive';

interface Step09Props {
  identitySettings: {
    login_max_retries: number;
    login_lockout_duration: number;
    login_honeypot_usernames: string[];
    two_factor_enabled: boolean;
    two_factor_policy: string;
    two_factor_grace_days: number;
    two_factor_roles: string[];
    passkeys_enabled: boolean;
    strong_passwords_enabled: boolean;
    hibp_check_enabled: boolean;
    disable_xmlrpc: boolean;
    disable_user_enumeration: boolean;
    hide_wp_version: boolean;
  };
  setIdentitySettings: React.Dispatch<React.SetStateAction<any>>;
}

export const Step09Login2faPasskeys: React.FC<Step09Props> = ({
  identitySettings,
  setIdentitySettings,
}) => {
  const handleHoneypotChange = (val: string) => {
    const list = val.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
    setIdentitySettings((prev: any) => ({ ...prev, login_honeypot_usernames: list }));
  };

  const handleRoleToggle = (role: string) => {
    const roles = identitySettings.two_factor_roles || ['administrator'];
    const exists = roles.includes(role);
    const updated = exists ? roles.filter((r) => r !== role) : [...roles, role];
    setIdentitySettings((prev: any) => ({ ...prev, two_factor_roles: updated }));
  };

  return (
    <div className="webcare-wizard-step-container" style={{ display: 'flex', flexDirection: 'column', gap: '24px', width: '100%', minWidth: 0, boxSizing: 'border-box' }}>
      {/* Step Header */}
      <div>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '4px 10px', borderRadius: '20px', background: 'var(--webcare-primary-soft, rgba(79, 70, 229, 0.08))', color: 'var(--webcare-primary, #4f46e5)', fontSize: '12px', fontWeight: 700, marginBottom: '12px' }}>
          <Lock size={14} /> Phase 3: Identity &amp; OS Hardening
        </div>
        <h1 style={{ margin: '0 0 10px 0', fontSize: '24px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)' }}>
          Zero-Trust Identity, 2FA &amp; Passkeys
        </h1>
        <p style={{ fontSize: '14px', lineHeight: 1.6, color: 'var(--webcare-text-secondary, #475569)', margin: 0 }}>
          Harden administrator authentication with brute-force rate limits, honeypot username traps, mandatory 2FA enforcement, and hardware WebAuthn passkeys.
        </p>
      </div>

      {/* Brute-Force Rate Limiting & Honeypots */}
      <div style={{ padding: '20px', borderRadius: '12px', background: 'var(--webcare-bg-panel, #ffffff)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
        <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)', marginBottom: '14px' }}>
          Brute-Force Shield &amp; Honeypot Traps
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '16px', marginBottom: '16px' }}>
          {/* Max Retries */}
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
              <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-title, #0f172a)' }}>
                Max Allowed Login Failures (<code>login_max_retries</code>):
              </label>
              <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-primary, #4f46e5)' }}>
                {identitySettings.login_max_retries} attempts
              </span>
            </div>
            <input
              type="range"
              min={3}
              max={15}
              value={identitySettings.login_max_retries}
              onChange={(e) => setIdentitySettings((prev: any) => ({ ...prev, login_max_retries: parseInt(e.target.value, 10) }))}
              style={{ width: '100%', accentColor: 'var(--webcare-primary, #4f46e5)' }}
            />
          </div>

          {/* Lockout Duration */}
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
              <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-title, #0f172a)' }}>
                Lockout Duration (<code>login_lockout_duration</code>):
              </label>
              <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-primary, #4f46e5)' }}>
                {identitySettings.login_lockout_duration} minutes
              </span>
            </div>
            <input
              type="range"
              min={15}
              max={240}
              step={15}
              value={identitySettings.login_lockout_duration}
              onChange={(e) => setIdentitySettings((prev: any) => ({ ...prev, login_lockout_duration: parseInt(e.target.value, 10) }))}
              style={{ width: '100%', accentColor: 'var(--webcare-primary, #4f46e5)' }}
            />
          </div>
        </div>

        {/* Honeypot Usernames */}
        <div>
          <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-title, #0f172a)', marginBottom: '4px' }}>
            Instant-Lockout Honeypot Usernames (comma-separated):
          </label>
          <input
            type="text"
            value={(identitySettings.login_honeypot_usernames || []).join(', ')}
            onChange={(e) => handleHoneypotChange(e.target.value)}
            placeholder="admin, administrator, root, test, wpadmin, guest"
            className="webcare-firewall-input"
            style={{ width: '100%', padding: '8px 12px', fontSize: '12px', borderRadius: '6px' }}
          />
          <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px' }}>
            Any IP attempting to log in with these usernames is banned immediately without consuming retry attempts.
          </div>
        </div>
      </div>

      {/* 2FA & WebAuthn Passkeys */}
      <div style={{ padding: '20px', borderRadius: '12px', background: 'var(--webcare-bg-elevated, #f8fafc)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
        <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)', marginBottom: '14px' }}>
          Two-Factor Authentication (2FA) &amp; WebAuthn Passkeys
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '12px', marginBottom: '16px' }}>
          {/* 2FA Master */}
          <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', padding: '12px', borderRadius: '8px', background: 'var(--webcare-bg-panel, #ffffff)', border: '1px solid var(--webcare-border, #cbd5e1)', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={identitySettings.two_factor_enabled}
              onChange={(e) => setIdentitySettings((prev: any) => ({ ...prev, two_factor_enabled: e.target.checked }))}
              style={{ marginTop: '2px', accentColor: 'var(--webcare-primary, #4f46e5)' }}
            />
            <div>
              <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                Two-Factor Authentication (TOTP)
              </div>
              <div style={{ fontSize: '11px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px' }}>
                Google Authenticator, 1Password, Authy compatible TOTP.
              </div>
            </div>
          </label>

          {/* Passkeys */}
          <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', padding: '12px', borderRadius: '8px', background: 'var(--webcare-bg-panel, #ffffff)', border: '1px solid var(--webcare-border, #cbd5e1)', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={identitySettings.passkeys_enabled}
              onChange={(e) => setIdentitySettings((prev: any) => ({ ...prev, passkeys_enabled: e.target.checked }))}
              style={{ marginTop: '2px', accentColor: 'var(--webcare-primary, #4f46e5)' }}
            />
            <div>
              <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                FIDO2 / WebAuthn Passkeys
              </div>
              <div style={{ fontSize: '11px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px' }}>
                FaceID, TouchID, Windows Hello, and YubiKey hardware keys.
              </div>
            </div>
          </label>
        </div>

        {/* 2FA Enforcement Policy */}
        {identitySettings.two_factor_enabled && (
          <div style={{ padding: '14px', borderRadius: '8px', background: 'var(--webcare-bg-panel, #ffffff)', border: '1px solid var(--webcare-border, #cbd5e1)', display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)', marginBottom: '6px' }}>
                2FA Enforcement Policy:
              </label>
              <select
                value={identitySettings.two_factor_policy || 'grace_period'}
                onChange={(e) => setIdentitySettings((prev: any) => ({ ...prev, two_factor_policy: e.target.value }))}
                className="webcare-input"
                style={{ width: '100%', maxWidth: '340px', padding: '6px 12px', fontSize: '12px', borderRadius: '6px' }}
              >
                <option value="grace_period">Enforce After Grace Period (7 Days Default)</option>
                <option value="remind_login">Gentle Reminder on Login</option>
                <option value="immediate">Strict Immediate Enforcement on Next Login</option>
              </select>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)', marginBottom: '6px' }}>
                Roles Required to Use 2FA:
              </label>
              <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                {['administrator', 'editor', 'author', 'shop_manager'].map((role) => {
                  const isChecked = (identitySettings.two_factor_roles || []).includes(role);
                  return (
                    <label key={role} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', cursor: 'pointer', color: 'var(--webcare-text-title, #0f172a)' }}>
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={() => handleRoleToggle(role)}
                        style={{ accentColor: 'var(--webcare-primary, #4f46e5)' }}
                      />
                      <span style={{ textTransform: 'capitalize' }}>{role.replace('_', ' ')}</span>
                    </label>
                  );
                })}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Developer Deep Dive: HIBP Breach Checks, XML-RPC & User Enumeration */}
      <DeveloperDeepDive
        title="Developer Controls: HaveIBeenPwned API, XML-RPC & User Enumeration"
        badge="SettingsManager::auth_hardening"
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={identitySettings.hibp_check_enabled}
              onChange={(e) => setIdentitySettings((prev: any) => ({ ...prev, hibp_check_enabled: e.target.checked }))}
              style={{ marginTop: '2px', accentColor: 'var(--webcare-primary, #4f46e5)' }}
            />
            <div>
              <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-title, #0f172a)' }}>
                HaveIBeenPwned Breach Check (<code>hibp_check_enabled</code>)
              </div>
              <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)' }}>
                Checks user passwords against 800M+ pwned credentials using k-Anonymity SHA-1 hash prefixes (passwords are never transmitted).
              </div>
            </div>
          </label>

          <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={identitySettings.disable_xmlrpc}
              onChange={(e) => setIdentitySettings((prev: any) => ({ ...prev, disable_xmlrpc: e.target.checked }))}
              style={{ marginTop: '2px', accentColor: 'var(--webcare-primary, #4f46e5)' }}
            />
            <div>
              <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-title, #0f172a)' }}>
                Disable XML-RPC (<code>disable_xmlrpc</code>)
              </div>
              <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)' }}>
                Completely blocks <code>/xmlrpc.php</code> authentication vectors and pingback amplification DDoS.
              </div>
            </div>
          </label>

          <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={identitySettings.disable_user_enumeration}
              onChange={(e) => setIdentitySettings((prev: any) => ({ ...prev, disable_user_enumeration: e.target.checked }))}
              style={{ marginTop: '2px', accentColor: 'var(--webcare-primary, #4f46e5)' }}
            />
            <div>
              <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-title, #0f172a)' }}>
                Block Username Enumeration (<code>disable_user_enumeration</code>)
              </div>
              <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)' }}>
                Blocks <code>/?author=N</code> queries and guest requests to <code>/wp-json/wp/v2/users</code>.
              </div>
            </div>
          </label>

          <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={identitySettings.hide_wp_version}
              onChange={(e) => setIdentitySettings((prev: any) => ({ ...prev, hide_wp_version: e.target.checked }))}
              style={{ marginTop: '2px', accentColor: 'var(--webcare-primary, #4f46e5)' }}
            />
            <div>
              <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-title, #0f172a)' }}>
                Hide WordPress Generator Meta &amp; Asset Versions (<code>hide_wp_version</code>)
              </div>
              <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)' }}>
                Strips version strings from HTML head tags and script query parameters (e.g. <code>?ver=6.x</code>).
              </div>
            </div>
          </label>
        </div>
      </DeveloperDeepDive>
    </div>
  );
};
