import { useState, useEffect } from '@wordpress/element';
import { showConfirm } from '../utils/dialog';
import {
  Fingerprint,
  Key,
  Smartphone,
  Laptop,
  CheckCircle2,
  Trash2,
  Plus,
  RefreshCw,
  ShieldCheck,
  AlertTriangle,
  Info,
  Clock,
  Sparkles
} from 'lucide-react';

interface WebAuthnPasskeyCardProps {
  apiRequest: (options: any) => Promise<any>;
}

// Helper: base64url to Uint8Array
function base64urlToUint8Array(base64url: string): Uint8Array {
  let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  const raw = atob(base64);
  const buffer = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) {
    buffer[i] = raw.charCodeAt(i);
  }
  return buffer;
}

// Helper: ArrayBuffer to base64url
function arrayBufferToBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export const WebAuthnPasskeyCard: React.FC<WebAuthnPasskeyCardProps> = ({ apiRequest }) => {
  const [loading, setLoading] = useState<boolean>(true);
  const [credentials, setCredentials] = useState<any[]>([]);
  const [rpId, setRpId] = useState<string>('');
  const [registering, setRegistering] = useState<boolean>(false);
  const [testing, setTesting] = useState<boolean>(false);
  const [customLabel, setCustomLabel] = useState<string>('');
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const isWebAuthnSupported = typeof window !== 'undefined' && !!window.PublicKeyCredential;

  const fetchCredentials = async () => {
    setLoading(true);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/auth/webauthn/credentials',
        method: 'GET',
      });
      if (res?.success) {
        setCredentials(res.credentials || []);
        setRpId(res.rp_id || '');
      }
    } catch (err) {
      console.error('Failed to fetch WebAuthn credentials:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCredentials();
  }, []);

  const handleRegisterPasskey = async () => {
    if (!isWebAuthnSupported) {
      setFeedback({ type: 'error', message: 'Your browser or device does not support WebAuthn Passkeys.' });
      return;
    }

    setRegistering(true);
    setFeedback(null);
    try {
      const optRes = await apiRequest({
        path: '/webcare-pro-security/v1/auth/webauthn/register-options',
        method: 'GET',
      });

      if (!optRes?.success || !optRes.options) {
        throw new Error(optRes?.message || 'Failed to generate registration challenge.');
      }

      const opts = optRes.options;
      opts.challenge = base64urlToUint8Array(opts.challenge);
      opts.user.id = base64urlToUint8Array(opts.user.id);

      if (opts.excludeCredentials) {
        opts.excludeCredentials = opts.excludeCredentials.map((c: any) => ({
          ...c,
          id: base64urlToUint8Array(c.id),
        }));
      }

      // Prompt OS / hardware authenticator (FaceID, TouchID, Windows Hello)
      const credential = (await navigator.credentials.create({
        publicKey: opts,
      })) as any;

      if (!credential) {
        throw new Error('Passkey creation was cancelled.');
      }

      const responsePayload: any = {
        id: credential.id,
        rawId: arrayBufferToBase64url(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: arrayBufferToBase64url(credential.response.clientDataJSON),
          attestationObject: arrayBufferToBase64url(credential.response.attestationObject),
        },
      };

      // W3C Level 2 / Level 3: Extract direct DER public key if supported by browser
      if (typeof credential.response?.getPublicKey === 'function') {
        const pkBuffer = credential.response.getPublicKey();
        if (pkBuffer) {
          responsePayload.response.publicKey = arrayBufferToBase64url(pkBuffer);
        }
      }

      const verifyRes = await apiRequest({
        path: '/webcare-pro-security/v1/auth/webauthn/register-verify',
        method: 'POST',
        data: {
          payload: responsePayload,
          label: customLabel || undefined,
        },
      });

      if (verifyRes?.success) {
        setFeedback({
          type: 'success',
          message: verifyRes.message || 'Passkey registered successfully!',
        });
        setCustomLabel('');
        await fetchCredentials();
      } else {
        throw new Error(verifyRes?.message || 'Verification failed.');
      }
    } catch (err: any) {
      console.error('Passkey registration error:', err);
      setFeedback({
        type: 'error',
        message: err.name === 'NotAllowedError'
          ? 'Biometric prompt timed out or was cancelled by user.'
          : (err?.message || 'Failed to register Passkey.'),
      });
    } finally {
      setRegistering(false);
    }
  };

  const handleTestPasskey = async () => {
    if (!isWebAuthnSupported) return;

    setTesting(true);
    setFeedback(null);
    try {
      const optRes = await apiRequest({
        path: '/webcare-pro-security/v1/auth/webauthn/login-options',
        method: 'POST',
        data: {},
      });

      if (!optRes?.success || !optRes.options) {
        throw new Error(optRes?.message || 'Failed to fetch authentication options.');
      }

      const opts = optRes.options;
      opts.challenge = base64urlToUint8Array(opts.challenge);

      if (opts.allowCredentials) {
        opts.allowCredentials = opts.allowCredentials.map((c: any) => ({
          ...c,
          id: base64urlToUint8Array(c.id),
        }));
      }

      const assertion = (await navigator.credentials.get({
        publicKey: opts,
      })) as any;

      if (!assertion) {
        throw new Error('Authentication cancelled.');
      }

      const assertionPayload = {
        id: assertion.id,
        rawId: assertion.rawId ? arrayBufferToBase64url(assertion.rawId) : undefined,
        type: assertion.type,
        response: {
          clientDataJSON: arrayBufferToBase64url(assertion.response.clientDataJSON),
          authenticatorData: arrayBufferToBase64url(assertion.response.authenticatorData),
          signature: arrayBufferToBase64url(assertion.response.signature),
          userHandle: assertion.response?.userHandle ? arrayBufferToBase64url(assertion.response.userHandle) : undefined,
        },
      };

      const verifyRes = await apiRequest({
        path: '/webcare-pro-security/v1/auth/webauthn/login-verify',
        method: 'POST',
        data: {
          session_id: optRes.session_id,
          payload: assertionPayload,
        },
      });

      if (verifyRes?.success) {
        setFeedback({
          type: 'success',
          message: 'Biometric Passkey authentication PASSED! Hardware cryptographic assertion verified.',
        });
        await fetchCredentials();
      } else {
        throw new Error(verifyRes?.message || 'Assertion failed.');
      }
    } catch (err: any) {
      console.error('Passkey test error:', err);
      setFeedback({
        type: 'error',
        message: err.name === 'NotAllowedError'
          ? 'Biometric test was cancelled.'
          : (err?.message || 'Authentication assertion failed.'),
      });
    } finally {
      setTesting(false);
    }
  };

  const handleDeletePasskey = async (credentialId: string) => {
    const confirmed = await showConfirm({
      title: 'Revoke Passkey',
      message: 'Are you sure you want to revoke and delete this biometric Passkey?',
      confirmLabel: 'Revoke Passkey',
      variant: 'danger',
    });
    if (!confirmed) {
      return;
    }
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/auth/webauthn/delete-credential',
        method: 'POST',
        data: { credential_id: credentialId },
      });
      if (res?.success) {
        setFeedback({ type: 'success', message: 'Passkey revoked successfully.' });
        setCredentials(res.credentials || []);
      }
    } catch (err: any) {
      setFeedback({ type: 'error', message: err?.message || 'Failed to delete passkey.' });
    }
  };

  return (
    <div className="webcare-waf-table-card" style={{ padding: '24px' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px', marginBottom: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{ width: '42px', height: '42px', borderRadius: '12px', background: 'rgba(16, 185, 129, 0.14)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#10b981' }}>
            <Fingerprint size={24} />
          </div>
          <div>
            <h2 style={{ fontSize: '18px', fontWeight: 700, margin: 0, color: 'var(--webcare-text-title, #0f172a)' }}>
              Frictionless Passkeys & Biometrics (FIDO2 / WebAuthn)
            </h2>
            <p style={{ margin: 0, fontSize: '13px', color: 'var(--webcare-text-muted, #64748b)' }}>
              Sign in instantly using Apple TouchID, FaceID, Windows Hello, or Android Biometrics without passwords or OTP codes.
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>Relying Party:</span>
          <code style={{ fontSize: '12px', background: 'rgba(56, 189, 248, 0.1)', color: '#0284c7', padding: '3px 8px', borderRadius: '6px' }}>
            {rpId || 'localhost'}
          </code>
        </div>
      </div>

      {feedback && (
        <div
          style={{
            padding: '12px 16px',
            borderRadius: '8px',
            marginBottom: '20px',
            fontSize: '13px',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            background: feedback.type === 'success' ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)',
            border: feedback.type === 'success' ? '1px solid rgba(16, 185, 129, 0.3)' : '1px solid rgba(239, 68, 68, 0.3)',
            color: feedback.type === 'success' ? '#10b981' : '#dc2626',
          }}
        >
          {feedback.type === 'success' ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
          <span>{feedback.message}</span>
        </div>
      )}

      {!isWebAuthnSupported && (
        <div style={{ padding: '14px 18px', borderRadius: '10px', background: 'rgba(245, 158, 11, 0.12)', border: '1px solid rgba(245, 158, 11, 0.3)', color: '#d97706', fontSize: '13px', marginBottom: '20px' }}>
          <strong>Notice:</strong> Your current browser does not expose the W3C WebAuthn API. Passkeys require HTTPS and modern browsers (Safari, Chrome, Edge, Firefox).
        </div>
      )}

      {/* Register Passkey Form Bar */}
      <div style={{ background: 'var(--webcare-bg-surface, #f8fafc)', border: '1px solid var(--webcare-border, #e2e8f0)', borderRadius: '12px', padding: '18px', marginBottom: '24px' }}>
        <h3 style={{ fontSize: '14px', fontWeight: 700, margin: '0 0 10px', color: 'var(--webcare-text-title, #0f172a)' }}>
          Register a New Device / Biometric Passkey
        </h3>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          <input
            type="text"
            className="webcare-input"
            placeholder="Custom Device Name (e.g. Work MacBook, Personal iPhone)"
            value={customLabel}
            onChange={(e) => setCustomLabel(e.target.value)}
            style={{ flex: 1, minWidth: '260px' }}
          />

          <button
            type="button"
            className="webcare-btn webcare-btn-primary"
            onClick={handleRegisterPasskey}
            disabled={registering || !isWebAuthnSupported}
            style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
          >
            {registering ? (
              <>
                <RefreshCw size={14} className="webcare-spin" />
                <span>Prompting Biometrics...</span>
              </>
            ) : (
              <>
                <Plus size={14} />
                <span>Add Biometric Passkey</span>
              </>
            )}
          </button>

          {credentials.length > 0 && (
            <button
              type="button"
              className="webcare-btn webcare-btn-secondary"
              onClick={handleTestPasskey}
              disabled={testing || !isWebAuthnSupported}
              style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
            >
              {testing ? (
                <>
                  <RefreshCw size={14} className="webcare-spin" />
                  <span>Verifying Hardware...</span>
                </>
              ) : (
                <>
                  <Sparkles size={14} />
                  <span>Test Biometric Authentication</span>
                </>
              )}
            </button>
          )}
        </div>
      </div>

      {/* Registered Passkeys List */}
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
          <h3 style={{ fontSize: '15px', fontWeight: 700, margin: 0, color: 'var(--webcare-text-title, #0f172a)' }}>
            Registered Passkeys ({credentials.length})
          </h3>
        </div>

        {loading ? (
          <p style={{ color: 'var(--webcare-text-muted, #64748b)', fontSize: '13px' }}>Loading passkeys...</p>
        ) : credentials.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '36px 20px', background: 'var(--webcare-bg-surface, #f8fafc)', borderRadius: '12px', border: '1px dashed var(--webcare-border, #e2e8f0)' }}>
            <Key size={32} color="#94a3b8" style={{ marginBottom: '10px' }} />
            <h4 style={{ margin: '0 0 6px', fontSize: '14px', fontWeight: 600, color: 'var(--webcare-text-title, #0f172a)' }}>
              No Biometric Passkeys Registered Yet
            </h4>
            <p style={{ margin: 0, fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
              Click "Add Biometric Passkey" above to pair your Mac TouchID, iPhone FaceID, or Windows Hello.
            </p>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {credentials.map((cred, idx) => (
              <div
                key={cred.credential_id || idx}
                className="webcare-firewall-rule-card"
                style={{ padding: '16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '14px' }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                  <div style={{ width: '38px', height: '38px', borderRadius: '10px', background: 'rgba(56, 189, 248, 0.14)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#0284c7' }}>
                    <Fingerprint size={20} />
                  </div>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '2px' }}>
                      <span style={{ fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                        {cred.name || 'Hardware Passkey'}
                      </span>
                      <span className="webcare-badge-pill webcare-badge-clean">
                        FIDO2 Active
                      </span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
                      <span>Registered: {new Date(cred.created_at * 1000).toLocaleDateString()}</span>
                      {cred.last_used && (
                        <span>Last used: {new Date(cred.last_used * 1000).toLocaleDateString()}</span>
                      )}
                      <span>Sign count: {cred.sign_count || 0}</span>
                    </div>
                  </div>
                </div>

                <button
                  type="button"
                  className="webcare-btn webcare-btn-danger"
                  onClick={() => handleDeletePasskey(cred.credential_id)}
                  style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
                >
                  <Trash2 size={13} />
                  <span>Revoke</span>
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default WebAuthnPasskeyCard;
