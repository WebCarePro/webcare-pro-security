import { useState } from '@wordpress/element';
import { Search, ShieldCheck, Unlock, AlertCircle, Clock, Globe, ArrowRight, CheckCircle2, UserCheck, RefreshCw } from 'lucide-react';

interface CustomerLockoutProps {
  apiRequest: (options: any) => Promise<any>;
}

export const CustomerLockoutCard = ({ apiRequest }: CustomerLockoutProps) => {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [unblocking, setUnblocking] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [message, setMessage] = useState<{ type: 'success' | 'error' | 'info'; text: string } | null>(null);

  const handleLookup = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!query.trim()) return;

    setLoading(true);
    setMessage(null);
    setResult(null);

    try {
      const res = await apiRequest({
        path: `/webcare-pro-security/v1/firewall/customer/lookup-block?code=${encodeURIComponent(query.trim())}`,
        method: 'GET',
      });

      if (res && res.found) {
        setResult(res);
      } else {
        setMessage({
          type: 'info',
          text: res?.message || 'No active lockout record found for this Support Reference Code or IP. The visitor may already be unblocked or the block event expired.',
        });
      }
    } catch (err: any) {
      setMessage({
        type: 'error',
        text: err?.message || 'Failed to search lockout record.',
      });
    } finally {
      setLoading(false);
    }
  };

  const handleUnblock = async () => {
    if (!result?.client_ip) return;

    setUnblocking(true);
    setMessage(null);

    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/firewall/customer/unblock',
        method: 'POST',
        data: {
          ip: result.client_ip,
          code: result.ref_code,
        },
      });

      if (res && res.success) {
        setMessage({
          type: 'success',
          text: res.message || `Customer IP ${result.client_ip} has been unblocked and granted 24-hour checkout access.`,
        });
        setResult(null);
        setQuery('');
      } else {
        setMessage({
          type: 'error',
          text: res?.message || 'Failed to unblock customer.',
        });
      }
    } catch (err: any) {
      setMessage({
        type: 'error',
        text: err?.message || 'Error occurred while unblocking.',
      });
    } finally {
      setUnblocking(false);
    }
  };

  return (
    <div
      className="webcare-card webcare-customer-lockout-hero"
      style={{
        marginBottom: 24,
        padding: '24px 28px',
        borderRadius: 14,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 20 }}>
        {/* Left column: Title & reassurance */}
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 14, flex: '1 1 360px', minWidth: 280 }}>
          <div
            className="webcare-lockout-badge-icon"
            style={{
              width: 44,
              height: 44,
              borderRadius: 12,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#ffffff',
              flexShrink: 0,
            }}
          >
            <UserCheck size={22} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <h3 className="webcare-lockout-title" style={{ margin: 0, fontSize: 17, fontWeight: 700, letterSpacing: '-0.01em' }}>
                Customer Lockout Finder
              </h3>
              <span className="webcare-lockout-pill">
                1-Click Unblock
              </span>
            </div>
            <p className="webcare-lockout-subtitle" style={{ margin: '4px 0 0', fontSize: 13, lineHeight: 1.5 }}>
              Has a paying customer or shopper been blocked during checkout or login? Enter their <strong>6-character Support Code</strong> (e.g. <code>#WEBCARE-492A</code>) or IP to instantly unblock them.
            </p>
          </div>
        </div>

        {/* Right column: Search form + quick chips */}
        <div style={{ flex: '1 1 420px', minWidth: 320 }}>
          <form onSubmit={handleLookup} style={{ display: 'flex', gap: 8 }}>
            <div style={{ position: 'relative', flex: 1 }}>
              <Search size={16} className="webcare-lockout-search-icon" style={{ position: 'absolute', left: 14, top: 13 }} />
              <input
                type="text"
                className="webcare-input webcare-lockout-input"
                placeholder="Enter Support Code (e.g. #WEBCARE-492A) or IP..."
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                style={{
                  width: '100%',
                  paddingLeft: 40,
                  paddingRight: 12,
                  height: 42,
                  fontSize: 14,
                  fontWeight: 600,
                  fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
                  borderRadius: 10,
                }}
              />
            </div>
            <button
              type="submit"
              disabled={loading || !query.trim()}
              className="webcare-btn webcare-btn-primary webcare-lockout-search-btn"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: '0 20px',
                height: 42,
                borderRadius: 10,
                fontSize: 14,
                fontWeight: 600,
                whiteSpace: 'nowrap',
              }}
            >
              {loading ? <RefreshCw size={15} className="webcare-spin-icon" /> : <Search size={15} />}
              <span>{loading ? 'Searching...' : 'Find Block'}</span>
            </button>
          </form>

          <div className="webcare-lockout-tip" style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 8, fontSize: 11 }}>
            <span>Tip: Customers see their 6-character code directly on the 403 block screen.</span>
          </div>
        </div>
      </div>

      {message && (
        <div
          className={`webcare-lockout-alert is-${message.type}`}
          style={{
            marginTop: 16,
            padding: '12px 16px',
            borderRadius: 10,
            fontSize: 13,
            display: 'flex',
            alignItems: 'center',
            gap: 10,
          }}
        >
          {message.type === 'success' ? <CheckCircle2 size={18} color="#16a34a" /> : <AlertCircle size={18} />}
          <span style={{ fontWeight: 500 }}>{message.text}</span>
        </div>
      )}

      {result && (
        <div
          className="webcare-lockout-result-panel"
          style={{
            marginTop: 18,
            padding: '20px 24px',
            borderRadius: 12,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
            <div style={{ flex: '1 1 380px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                <span className="webcare-lockout-status-badge">
                  BLOCKED REQUEST
                </span>
                <span className="webcare-lockout-ref-code">
                  {result.ref_code}
                </span>
                <span className="webcare-lockout-timestamp" style={{ fontSize: 12 }}>• {result.formatted_time}</span>
              </div>

              <p className="webcare-lockout-reason" style={{ margin: '8px 0 12px', fontSize: 14, fontWeight: 600, lineHeight: 1.5 }}>
                {result.friendly_reason}
              </p>

              <div className="webcare-lockout-meta-row" style={{ display: 'flex', gap: 20, fontSize: 12, flexWrap: 'wrap' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Globe size={14} color="#0284c7" />
                  <span>IP Address: <strong>{result.client_ip}</strong></span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Clock size={14} color="#0284c7" />
                  <span>Triggered Rule: <strong>{result.lockout?.rule_name}</strong></span>
                </div>
              </div>
            </div>

            <div>
              <button
                type="button"
                onClick={handleUnblock}
                disabled={unblocking}
                className="webcare-btn webcare-lockout-unblock-btn"
                style={{
                  color: '#ffffff',
                  fontWeight: 700,
                  fontSize: 14,
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                  padding: '11px 22px',
                  borderRadius: 10,
                  cursor: 'pointer',
                  border: 'none',
                }}
              >
                {unblocking ? <RefreshCw size={17} className="webcare-spin-icon" /> : <Unlock size={17} />}
                <span>{unblocking ? 'Restoring Access...' : 'Unblock & Allow for 24 Hours'}</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
