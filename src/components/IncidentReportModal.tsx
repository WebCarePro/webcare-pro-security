import { useState, useEffect } from '@wordpress/element';
import { showAlert } from '../utils/dialog';
import { 
  FileText, 
  Printer, 
  Download, 
  X, 
  ShieldCheck, 
  ShieldAlert, 
  CheckCircle, 
  Layers, 
  Terminal,
  ExternalLink,
  Info
} from 'lucide-react';

interface IncidentReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  siteName?: string;
}

export default function IncidentReportModal({
  isOpen,
  onClose,
  siteName = '',
}: IncidentReportModalProps) {
  const [clientName, setClientName] = useState<string>(siteName);
  const [auditorNotes, setAuditorNotes] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [previewData, setPreviewData] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  // Keyboard shortcut: Escape to close
  useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  // Initialize client name if siteName changes
  useEffect(() => {
    if (siteName && !clientName) {
      setClientName(siteName);
    }
  }, [siteName]);

  // Fetch quick report telemetry when modal opens
  useEffect(() => {
    if (!isOpen) return;

    let isMounted = true;
    setLoading(true);
    setError(null);

    const nonce = (window as any).webcareScannerSettings?.nonce || '';
    const rootUrl = (window as any).webcareScannerSettings?.restUrl || '/wp-json/';
    const endpoint = `${rootUrl}webcare-pro-security/v1/reports/incident-response?format=json`;

    fetch(endpoint, {
      headers: {
        'X-WP-Nonce': nonce,
      },
    })
      .then((res) => {
        if (!res.ok) throw new Error('Failed to load incident report preview.');
        return res.json();
      })
      .then((data) => {
        if (isMounted) {
          setPreviewData(data);
          if (!clientName && data?.client?.name) {
            setClientName(data.client.name);
          }
          setLoading(false);
        }
      })
      .catch((err) => {
        if (isMounted) {
          setError(err.message || 'Error loading report metrics.');
          setLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, [isOpen]);

  if (!isOpen) return null;

  const nonce = (window as any).webcareScannerSettings?.nonce || '';
  const rootUrl = (window as any).webcareScannerSettings?.restUrl || '/wp-json/';

  // Handle Open & Print PDF
  const handleOpenPrintHtml = () => {
    const params = new URLSearchParams({
      format: 'html',
      client_name: clientName || '',
      auditor_notes: auditorNotes || '',
      _wpnonce: nonce,
    });
    const url = `${rootUrl}webcare-pro-security/v1/reports/incident-response?${params.toString()}`;
    window.open(url, '_blank', 'noopener,noreferrer');
  };

  // Handle SIEM JSON Download
  const handleDownloadJSON = async () => {
    try {
      const params = new URLSearchParams({
        format: 'json',
        client_name: clientName || '',
        auditor_notes: auditorNotes || '',
      });
      const url = `${rootUrl}webcare-pro-security/v1/reports/incident-response?${params.toString()}`;
      
      const res = await fetch(url, {
        headers: { 'X-WP-Nonce': nonce },
      });
      if (!res.ok) throw new Error('Failed to download JSON report');
      const data = await res.json();

      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json;charset=utf-8' });
      const dlUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      const safeName = (clientName || 'site').toLowerCase().replace(/[^a-z0-9]/g, '-');
      a.href = dlUrl;
      a.download = `webcare-incident-report-${safeName}-${new Date().toISOString().slice(0, 10)}.json`;
      document.body.appendChild(a);
      a.click();
      setTimeout(() => {
        document.body.removeChild(a);
        URL.revokeObjectURL(dlUrl);
      }, 200);
    } catch (err: any) {
      await showAlert(`Download error: ${err?.message || 'Could not save JSON file.'}`, 'Download Error');
    }
  };

  const posture = previewData?.posture || {};
  const grade = posture?.letter_grade || 'A';
  const score = posture?.health_score ?? 100;
  const gradeColor = posture?.grade_color || '#10b981';
  const gradeLabel = posture?.grade_label || 'Hardened Posture';

  return (
    <div 
      className="webcare-modal-backdrop"
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(15, 23, 42, 0.75)',
        backdropFilter: 'blur(4px)',
        zIndex: 99999,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '20px',
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div 
        className="webcare-modal-window webcare-incident-modal"
        style={{
          width: '100%',
          maxWidth: '720px',
          background: '#0f172a',
          border: '1px solid #334155',
          borderRadius: '16px',
          boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.5)',
          overflow: 'hidden',
          display: 'flex',
          flexDirection: 'column',
          maxHeight: '90vh',
        }}
      >
        {/* Modal Header */}
        <div 
          className="webcare-modal-header"
          style={{
            padding: '20px 24px',
            borderBottom: '1px solid #1e293b',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: 'linear-gradient(to right, #0f172a, #1e293b)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{
              width: '40px',
              height: '40px',
              borderRadius: '10px',
              background: '#0284c7',
              color: '#ffffff',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: '0 0 15px rgba(2, 132, 199, 0.4)',
            }}>
              <FileText size={20} />
            </div>
            <div>
              <h3 
                className="webcare-file-viewer-title"
                style={{ margin: 0, fontSize: '17px', fontWeight: 800, color: '#ffffff' }}
              >
                Executive Incident Response &amp; Security Posture Report
              </h3>
              <p style={{ margin: '2px 0 0', fontSize: '12px', color: '#94a3b8' }}>
                Board-ready executive PDF report with Letter Grade, attack timeline &amp; SIEM export
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            style={{
              background: 'transparent',
              border: 'none',
              color: '#94a3b8',
              cursor: 'pointer',
              padding: '6px',
              borderRadius: '6px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
            onMouseEnter={(e) => (e.currentTarget.style.color = '#f8fafc')}
            onMouseLeave={(e) => (e.currentTarget.style.color = '#94a3b8')}
          >
            <X size={20} />
          </button>
        </div>

        {/* Modal Body */}
        <div style={{ padding: '24px', overflowY: 'auto', flex: 1 }}>
          {error && (
            <div style={{
              background: '#450a0a',
              border: '1px solid #991b1b',
              color: '#fca5a5',
              padding: '12px 16px',
              borderRadius: '8px',
              fontSize: '13px',
              marginBottom: '20px',
            }}>
              {error}
            </div>
          )}

          {/* Quick Posture Preview Banner */}
          <div style={{
            background: 'linear-gradient(135deg, #1e293b 0%, #0f172a 100%)',
            border: '1px solid #334155',
            borderRadius: '12px',
            padding: '18px 20px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            marginBottom: '24px',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '18px' }}>
              <div style={{
                width: '64px',
                height: '64px',
                borderRadius: '50%',
                background: gradeColor,
                color: '#ffffff',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                fontWeight: 900,
                boxShadow: `0 0 20px ${gradeColor}55`,
                border: '3px solid rgba(255,255,255,0.2)',
              }}>
                <div style={{ fontSize: '26px', lineHeight: 1 }}>{grade}</div>
                <div style={{ fontSize: '8px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Grade</div>
              </div>
              <div>
                <div style={{ fontSize: '15px', fontWeight: 700, color: '#f8fafc' }}>
                  {gradeLabel} ({score}/100)
                </div>
                <div style={{ fontSize: '12px', color: '#94a3b8', marginTop: '3px' }}>
                  {previewData?.posture?.counts?.critical ?? 0} critical threats &bull; {previewData?.posture?.active_chains ?? 0} attack chains &bull; {previewData?.posture?.active_patches ?? 0} virtual patches
                </div>
              </div>
            </div>

            <div style={{ textAlign: 'right', fontSize: '11px', color: '#64748b' }}>
              <div>Report ID: <strong style={{ color: '#cbd5e1' }}>{previewData?.report_id || 'Generating...'}</strong></div>
              <div style={{ marginTop: '2px' }}>Audit Engine v{previewData?.version || '1.15.0'}</div>
            </div>
          </div>

          {/* Configuration Inputs */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#cbd5e1', marginBottom: '6px' }}>
                Client / Organization Name (Branding)
              </label>
              <input
                type="text"
                value={clientName}
                onChange={(e) => setClientName(e.target.value)}
                placeholder="e.g. Acme Corporation or Production Site"
                style={{
                  width: '100%',
                  background: '#1e293b',
                  border: '1px solid #334155',
                  borderRadius: '8px',
                  padding: '10px 14px',
                  color: '#f8fafc',
                  fontSize: '13px',
                  outline: 'none',
                }}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#cbd5e1', marginBottom: '6px' }}>
                Executive Auditor Certification (Solo Freelancer)
              </label>
              <div style={{
                background: '#1e293b',
                border: '1px solid #334155',
                borderRadius: '8px',
                padding: '10px 14px',
                fontSize: '12px',
                color: '#94a3b8',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}>
                <div>
                  <strong style={{ color: '#38bdf8' }}>Mir Alamin (WebCare Pro)</strong>
                  <span style={{ color: '#64748b', marginLeft: '6px' }}>
                    &mdash; Senior Linux SysAdmin &amp; WordPress Security Engineer
                  </span>
                </div>
                <span style={{
                  fontSize: '10px',
                  background: '#0284c722',
                  color: '#38bdf8',
                  padding: '2px 8px',
                  borderRadius: '4px',
                  fontWeight: 600,
                }}>
                  Direct 1-on-1 Certified
                </span>
              </div>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#cbd5e1', marginBottom: '6px' }}>
                Auditor Commentary &amp; Custom Instructions (Optional)
              </label>
              <textarea
                value={auditorNotes}
                onChange={(e) => setAuditorNotes(e.target.value)}
                rows={3}
                placeholder="Add executive remarks, business impact context, or emergency change-window instructions for the client..."
                style={{
                  width: '100%',
                  background: '#1e293b',
                  border: '1px solid #334155',
                  borderRadius: '8px',
                  padding: '10px 14px',
                  color: '#f8fafc',
                  fontSize: '13px',
                  outline: 'none',
                  resize: 'vertical',
                }}
              />
            </div>

            {/* Scope inclusions info */}
            <div style={{
              background: '#0b1329',
              border: '1px solid #1e3a8a',
              borderRadius: '8px',
              padding: '12px 16px',
              display: 'flex',
              alignItems: 'flex-start',
              gap: '10px',
            }}>
              <Info size={16} color="#60a5fa" style={{ flexShrink: 0, marginTop: '2px' }} />
              <div style={{ fontSize: '12px', color: '#93c5fd', lineHeight: 1.5 }}>
                The generated executive report automatically consolidates:
                <strong> Multi-Persistence Sentinel vectors</strong> (Phase 1),
                <strong> MITRE ATT&CK Behavioral Chains</strong> (Phase 2),
                <strong> Active Two-Tier Virtual Patches</strong> (Phase 3), and
                <strong> Remediated Incident Ledgers</strong> into a single audit deliverable.
              </div>
            </div>
          </div>
        </div>

        {/* Modal Footer / Actions */}
        <div style={{
          padding: '16px 24px',
          borderTop: '1px solid #1e293b',
          background: '#090d16',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}>
          <button
            type="button"
            onClick={onClose}
            style={{
              padding: '9px 16px',
              borderRadius: '8px',
              border: '1px solid #334155',
              background: 'transparent',
              color: '#94a3b8',
              fontSize: '13px',
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Cancel
          </button>

          <div style={{ display: 'flex', gap: '10px' }}>
            <button
              type="button"
              onClick={handleDownloadJSON}
              disabled={loading}
              style={{
                padding: '9px 16px',
                borderRadius: '8px',
                border: '1px solid #38bdf8',
                background: 'rgba(56, 189, 248, 0.1)',
                color: '#38bdf8',
                fontSize: '13px',
                fontWeight: 700,
                cursor: loading ? 'not-allowed' : 'pointer',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              <Download size={15} />
              SIEM JSON Export
            </button>

            <button
              type="button"
              onClick={handleOpenPrintHtml}
              disabled={loading}
              style={{
                padding: '9px 20px',
                borderRadius: '8px',
                border: 'none',
                background: 'linear-gradient(to right, #0284c7, #0369a1)',
                color: '#ffffff',
                fontSize: '13px',
                fontWeight: 700,
                cursor: loading ? 'not-allowed' : 'pointer',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                boxShadow: '0 4px 12px rgba(2, 132, 199, 0.3)',
              }}
            >
              <Printer size={15} />
              Open &amp; Print Executive PDF
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
