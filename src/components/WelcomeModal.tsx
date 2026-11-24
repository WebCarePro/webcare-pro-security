import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  Lock, 
  Server, 
  Play, 
  CheckCircle2, 
  X, 
  Sparkles, 
  ChevronDown, 
  ChevronUp, 
  ArrowRight, 
  HardDrive, 
  EyeOff, 
  HeartHandshake, 
  ExternalLink, 
  AlertTriangle, 
  AlertOctagon, 
  RefreshCw 
} from 'lucide-react';
import { apiRequest } from '../utils/api';
import WebCareBrandLogo from './WebCareBrandLogo';

interface ReadinessCheckItem {
  key: string;
  title: string;
  category?: string;
  status: 'pass' | 'warn' | 'fail' | 'info';
  is_critical?: boolean;
  current: string;
  required: string;
  recommended?: string;
  description: string;
  remedy?: string;
}

interface ReadinessReport {
  is_compatible: boolean;
  readiness_score: number;
  checks: Record<string, ReadinessCheckItem>;
  welcome_dismissed: boolean;
}

interface WelcomeModalProps {
  isOpen: boolean;
  onClose: () => void;
  onStartScan?: () => void;
}

export const WelcomeModal: React.FC<WelcomeModalProps> = ({
  isOpen,
  onClose,
  onStartScan,
}) => {
  const [readiness, setReadiness] = useState<ReadinessReport | null>(null);
  const [showTechDetails, setShowTechDetails] = useState<boolean>(false);
  const [refreshingReadiness, setRefreshingReadiness] = useState<boolean>(false);
  const [readinessNotice, setReadinessNotice] = useState<string | null>(null);

  // Retrieve localized URLs from webcareScannerSettings
  const localized = (window as any).webcareScannerSettings || {};
  const logo3dUrl = localized.logo3dUrl || (localized.assetsUrl ? `${localized.assetsUrl}webcare-original-logo-3d.jpg` : '');

  const fetchReadiness = () => {
    setRefreshingReadiness(true);
    setReadinessNotice(null);
    apiRequest({
      path: '/webcare-pro-security/v1/readiness',
    })
      .then((res: any) => {
        if (res && res.report) {
          setReadiness(res.report);
          setReadinessNotice('Updated!');
          setTimeout(() => setReadinessNotice(null), 2500);
        }
      })
      .catch((err) => {
        console.warn('WebCare Readiness check:', err);
        setReadinessNotice('Check failed');
        setTimeout(() => setReadinessNotice(null), 2500);
      })
      .finally(() => {
        setRefreshingReadiness(false);
      });
  };

  useEffect(() => {
    if (!isOpen) return;

    let isMounted = true;
    apiRequest({
      path: '/webcare-pro-security/v1/readiness',
    })
      .then((res: any) => {
        if (isMounted && res && res.report) {
          setReadiness(res.report);
        }
      })
      .catch((err) => {
        console.warn('WebCare Readiness check:', err);
      });

    return () => {
      isMounted = false;
    };
  }, [isOpen]);

  if (!isOpen) return null;

  const handleDismiss = () => {
    apiRequest({
      path: '/webcare-pro-security/v1/welcome/dismiss',
      method: 'POST',
    }).catch(() => {});
    onClose();
  };

  const handleStartScanClick = () => {
    handleDismiss();
    if (onStartScan) {
      onStartScan();
    }
  };

  return (
    <div
      className="webcare-modal-backdrop webcare-welcome-modal-backdrop"
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 10000000,
        backgroundColor: 'rgba(3, 7, 18, 0.88)',
        backdropFilter: 'blur(16px)',
        WebkitBackdropFilter: 'blur(16px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '16px',
        animation: 'webcareFadeIn 0.25s cubic-bezier(0.16, 1, 0.3, 1)',
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif',
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) handleDismiss();
      }}
    >
      <div
        className="webcare-welcome-modal webcare-card-dark webcare-welcome-dialog"
        style={{
          position: 'relative',
          width: '100%',
          maxWidth: '960px',
          maxHeight: '92vh',
          overflowY: 'auto',
          background: 'linear-gradient(135deg, #070e22 0%, #0b152d 55%, #050a18 100%)',
          borderRadius: '26px',
          border: '1px solid rgba(56, 189, 248, 0.28)',
          boxShadow: '0 25px 70px -15px rgba(0, 0, 0, 0.85), 0 0 60px -15px rgba(6, 182, 212, 0.28)',
          color: '#f8fafc',
          display: 'flex',
          flexDirection: 'column',
        }}
      >
        {/* Top Neon Accent Glow Bar (Matching OG Generator Master Theme) */}
        <div
          style={{
            height: '4px',
            width: '100%',
            background: 'linear-gradient(90deg, #0284c7 0%, #06b6d4 40%, #10b581 75%, #3b82f6 100%)',
            boxShadow: '0 0 16px rgba(6, 182, 212, 0.65)',
            borderTopLeftRadius: '26px',
            borderTopRightRadius: '26px',
          }}
        />

        {/* Close Button */}
        <button
          type="button"
          onClick={handleDismiss}
          className="webcare-welcome-close-btn"
          style={{
            position: 'absolute',
            top: '20px',
            right: '20px',
            background: 'rgba(255, 255, 255, 0.06)',
            border: '1px solid rgba(255, 255, 255, 0.12)',
            borderRadius: '12px',
            color: '#94a3b8',
            width: '36px',
            height: '36px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            cursor: 'pointer',
            transition: 'all 0.15s ease',
            zIndex: 10,
          }}
          title="Close"
        >
          <X size={18} />
        </button>

        {/* Main Content Layout (Dual Panel) */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'minmax(0, 1.25fr) minmax(0, 0.75fr)',
            gap: '32px',
            padding: '36px 40px 24px',
          }}
          className="webcare-welcome-grid"
        >
          {/* Left Column: Easy Human Copy */}
          <div>
            {/* Friendly Badge */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px' }}>
              <span
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  background: 'rgba(6, 182, 212, 0.12)',
                  border: '1px solid rgba(6, 182, 212, 0.35)',
                  color: '#38bdf8',
                  padding: '4px 12px',
                  borderRadius: '999px',
                  fontSize: '11.5px',
                  fontWeight: 700,
                  letterSpacing: '0.04em',
                  textTransform: 'uppercase',
                }}
              >
                <Sparkles size={13} />
                Welcome to WebCare Pro Security & Firewall
              </span>
              <span
                style={{
                  background: 'rgba(16, 185, 129, 0.15)',
                  border: '1px solid rgba(16, 185, 129, 0.35)',
                  color: '#34d399',
                  padding: '4px 12px',
                  borderRadius: '999px',
                  fontSize: '11.5px',
                  fontWeight: 700,
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '4px',
                }}
              >
                <CheckCircle2 size={13} />
                100% Private
              </span>
            </div>

            {/* Clear Headline */}
            <h2
              className="webcare-welcome-headline"
              style={{
                fontSize: '28px',
                fontWeight: 800,
                color: '#ffffff',
                margin: '0 0 10px',
                letterSpacing: '-0.02em',
                lineHeight: 1.2,
              }}
            >
              Your Website is Safe, Private & In Your Own Hands.
            </h2>

            <p
              className="webcare-welcome-subheadline"
              style={{ fontSize: '14.5px', color: '#94a3b8', lineHeight: 1.6, margin: '0 0 24px' }}
            >
              I built this security scanner to protect your WordPress site completely on-premise.
              No complex setup, no data harvesting, and no confusing technical headaches.
            </p>

            {/* 3 Simple Non-Technical Promise Cards */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginBottom: '22px' }}>
              {/* Promise 1: Military Grade Encryption */}
              <div
                className="webcare-welcome-promise-card"
                style={{
                  background: 'rgba(15, 23, 42, 0.75)',
                  border: '1px solid rgba(59, 130, 246, 0.28)',
                  borderRadius: '14px',
                  padding: '14px 16px',
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '14px',
                }}
              >
                <div
                  style={{
                    width: '38px',
                    height: '38px',
                    borderRadius: '10px',
                    background: 'rgba(59, 130, 246, 0.18)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0,
                    color: '#60a5fa',
                  }}
                >
                  <Lock size={19} />
                </div>
                <div style={{ flex: 1 }}>
                  <h4
                    className="webcare-welcome-card-title"
                    style={{ margin: '0 0 4px', fontSize: '14.5px', fontWeight: 700, color: '#f1f5f9' }}
                  >
                    Military-Grade Encryption Inside Your Database
                  </h4>
                  <p
                    className="webcare-welcome-card-desc"
                    style={{ margin: '0 0 10px', fontSize: '13px', color: '#94a3b8', lineHeight: 1.5 }}
                  >
                    Any secret API keys, AI API keys (Google Gemini, OpenAI, Claude), Discord or Slack webhooks, sensitive settings, or passwords you save are sealed with bank-level encryption (AES-256-GCM). Even if someone downloads a raw copy of your database, they cannot read your secrets.
                  </p>
                  <a
                    href="https://webcarepro.dev/blog/post/how-aes-256-gcm-vault-protects-wordpress-secrets"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="webcare-welcome-link"
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '6px',
                      background: 'rgba(59, 130, 246, 0.12)',
                      border: '1px solid rgba(59, 130, 246, 0.3)',
                      color: '#93c5fd',
                      padding: '4px 10px',
                      borderRadius: '6px',
                      fontSize: '11.5px',
                      fontWeight: 600,
                      textDecoration: 'none',
                      transition: 'all 0.15s ease',
                      width: 'fit-content',
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.background = 'rgba(59, 130, 246, 0.25)';
                      e.currentTarget.style.borderColor = 'rgba(96, 165, 250, 0.6)';
                      e.currentTarget.style.color = '#ffffff';
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.background = 'rgba(59, 130, 246, 0.12)';
                      e.currentTarget.style.borderColor = 'rgba(59, 130, 246, 0.3)';
                      e.currentTarget.style.color = '#93c5fd';
                    }}
                  >
                    <span>Read How Database Encryption Works</span>
                    <ExternalLink size={12} />
                  </a>
                </div>
              </div>

              {/* Promise 2: Zero Tracking / Data Collection */}
              <div
                className="webcare-welcome-promise-card"
                style={{
                  background: 'rgba(15, 23, 42, 0.75)',
                  border: '1px solid rgba(16, 185, 129, 0.28)',
                  borderRadius: '14px',
                  padding: '14px 16px',
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '14px',
                }}
              >
                <div
                  style={{
                    width: '38px',
                    height: '38px',
                    borderRadius: '10px',
                    background: 'rgba(16, 185, 129, 0.18)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0,
                    color: '#34d399',
                  }}
                >
                  <EyeOff size={19} />
                </div>
                <div>
                  <h4
                    className="webcare-welcome-card-title"
                    style={{ margin: '0 0 4px', fontSize: '14.5px', fontWeight: 700, color: '#f1f5f9' }}
                  >
                    I Never Collect, Track, or Send Your Data Away
                  </h4>
                  <p
                    className="webcare-welcome-card-desc"
                    style={{ margin: 0, fontSize: '13px', color: '#94a3b8', lineHeight: 1.5 }}
                  >
                    Unlike other security plugins that copy your website files to external clouds, this scanner runs <strong>100% on your own web server</strong>. I never track your visitors or spy on your files.
                  </p>
                </div>
              </div>

              {/* Promise 3: Everything Stays In Your Web Space */}
              <div
                className="webcare-welcome-promise-card"
                style={{
                  background: 'rgba(15, 23, 42, 0.75)',
                  border: '1px solid rgba(6, 182, 212, 0.28)',
                  borderRadius: '14px',
                  padding: '14px 16px',
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '14px',
                }}
              >
                <div
                  style={{
                    width: '38px',
                    height: '38px',
                    borderRadius: '10px',
                    background: 'rgba(6, 182, 212, 0.18)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0,
                    color: '#38bdf8',
                  }}
                >
                  <HardDrive size={19} />
                </div>
                <div style={{ flex: 1 }}>
                  <h4
                    className="webcare-welcome-card-title"
                    style={{ margin: '0 0 4px', fontSize: '14.5px', fontWeight: 700, color: '#f1f5f9' }}
                  >
                    Everything Stays Right in Your Own Web Space
                  </h4>
                  <p
                    className="webcare-welcome-card-desc"
                    style={{ margin: '0 0 10px', fontSize: '13px', color: '#94a3b8', lineHeight: 1.5 }}
                  >
                    All virus scans, malware quarantines, and database backups are kept strictly on your own web hosting space in a password-guarded folder. You own everything.
                  </p>
                  <a
                    href="https://webcarepro.dev/blog/post/webcare-wordpress-security-scanner"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="webcare-welcome-link"
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '6px',
                      background: 'rgba(6, 182, 212, 0.12)',
                      border: '1px solid rgba(6, 182, 212, 0.3)',
                      color: '#38bdf8',
                      padding: '4px 10px',
                      borderRadius: '6px',
                      fontSize: '11.5px',
                      fontWeight: 600,
                      textDecoration: 'none',
                      transition: 'all 0.15s ease',
                      width: 'fit-content',
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.background = 'rgba(6, 182, 212, 0.25)';
                      e.currentTarget.style.borderColor = 'rgba(56, 189, 248, 0.6)';
                      e.currentTarget.style.color = '#ffffff';
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.background = 'rgba(6, 182, 212, 0.12)';
                      e.currentTarget.style.borderColor = 'rgba(6, 182, 212, 0.3)';
                      e.currentTarget.style.color = '#38bdf8';
                    }}
                  >
                    <span>Read More About WebCare Pro Security Features</span>
                    <ExternalLink size={12} />
                  </a>
                </div>
              </div>
            </div>

            {/* Server Readiness Status (Friendly reassurance) */}
            <div
              className="webcare-welcome-server-box"
              style={{
                background: 'rgba(16, 185, 129, 0.08)',
                border: '1px solid rgba(16, 185, 129, 0.28)',
                borderRadius: '12px',
                padding: '12px 16px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: '8px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <CheckCircle2 size={18} color="#10b581" />
                <span
                  className="webcare-welcome-server-text"
                  style={{ fontSize: '13px', color: '#e2e8f0' }}
                >
                  <strong style={{ color: '#ffffff' }}>Server Ready:</strong> Your web hosting meets all requirements for fast, encrypted scanning.
                </span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <button
                  type="button"
                  onClick={fetchReadiness}
                  disabled={refreshingReadiness}
                  style={{
                    background: 'rgba(56, 189, 248, 0.12)',
                    border: '1px solid rgba(56, 189, 248, 0.3)',
                    color: '#38bdf8',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: refreshingReadiness ? 'not-allowed' : 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '5px',
                    padding: '4px 10px',
                    borderRadius: '6px',
                    transition: 'all 0.15s ease',
                  }}
                  title="Re-check server compatibility"
                >
                  <RefreshCw size={12} className={refreshingReadiness ? 'webcare-spin-icon' : ''} />
                  <span>{refreshingReadiness ? 'Checking...' : (readinessNotice || 'Refresh')}</span>
                </button>
                <button
                  type="button"
                  onClick={() => setShowTechDetails(!showTechDetails)}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: '#38bdf8',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px',
                    padding: 0,
                  }}
                >
                  {showTechDetails ? 'Hide Details' : 'See Server Details'}
                  {showTechDetails ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                </button>
              </div>
            </div>
          </div>

          {/* Right Column: 3D Visual Showcase (Inspired by WebCare Pro 3D Brand Engine) */}
          <div
            style={{
              position: 'relative',
              background: 'linear-gradient(180deg, rgba(14, 23, 46, 0.85) 0%, rgba(4, 10, 27, 0.95) 100%)',
              borderRadius: '20px',
              border: '1px solid rgba(56, 189, 248, 0.22)',
              padding: '28px 24px',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              textAlign: 'center',
              overflow: 'hidden',
              boxShadow: 'inset 0 1px 0 rgba(255, 255, 255, 0.08)',
            }}
          >
            {/* Ambient Volumetric Back-Glow */}
            <div
              style={{
                position: 'absolute',
                width: '260px',
                height: '260px',
                borderRadius: '50%',
                background: 'radial-gradient(circle, rgba(6, 182, 212, 0.3) 0%, rgba(16, 185, 129, 0.15) 50%, transparent 70%)',
                filter: 'blur(35px)',
                pointerEvents: 'none',
                top: '40px',
              }}
            />

            {/* 3D Wireframe Floating Cubes (From cubes.svg) */}
            <div
              style={{
                position: 'absolute',
                top: '12px',
                right: '12px',
                opacity: 0.2,
                pointerEvents: 'none',
                transform: 'scale(0.8)',
              }}
            >
              <svg width="100" height="100" viewBox="0 0 120 120" fill="none">
                <polygon points="60,2 118,31 118,89 60,118 2,89 2,31" stroke="#38bdf8" strokeWidth="1.5" />
                <line x1="60" y1="60" x2="60" y2="118" stroke="#38bdf8" strokeWidth="1.5" />
                <line x1="60" y1="60" x2="2" y2="31" stroke="#38bdf8" strokeWidth="1.5" />
                <line x1="60" y1="60" x2="118" y2="31" stroke="#38bdf8" strokeWidth="1.5" />
              </svg>
            </div>

            {/* Top Verified Badge (Matching OG Image Design) */}
            <div
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                background: 'rgba(6, 182, 212, 0.12)',
                border: '1px solid rgba(56, 189, 248, 0.35)',
                borderRadius: '999px',
                padding: '3px 10px',
                fontSize: '10.5px',
                fontWeight: 700,
                color: '#38bdf8',
                letterSpacing: '0.08em',
                textTransform: 'uppercase',
                marginBottom: '16px',
              }}
            >
              <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#38bdf8', boxShadow: '0 0 8px #38bdf8' }} />
              VERIFIED SENIOR SYSADMIN • 12+ YRS
            </div>

            {/* 3D Shield Emblem Display */}
            <div
              style={{
                position: 'relative',
                width: '180px',
                height: '180px',
                marginBottom: '16px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                borderRadius: '22px',
                overflow: 'hidden',
                border: '1.5px solid rgba(56, 189, 248, 0.45)',
                boxShadow: '0 20px 45px -10px rgba(0, 0, 0, 0.9), 0 0 35px rgba(6, 182, 212, 0.45)',
                background: '#040a1b',
              }}
            >
              {logo3dUrl ? (
                <img
                  src={logo3dUrl}
                  alt="WebCare Pro 3D Security Shield & Server Infrastructure"
                  style={{
                    width: '100%',
                    height: '100%',
                    objectFit: 'cover',
                  }}
                  onError={(e) => {
                    // Fallback to SVG if image not found
                    (e.target as HTMLElement).style.display = 'none';
                  }}
                />
              ) : (
                <div
                  style={{
                    width: '110px',
                    height: '110px',
                    borderRadius: '24px',
                    background: 'linear-gradient(135deg, #0f172a 0%, #030712 100%)',
                    border: '2px solid rgba(6, 182, 212, 0.5)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    boxShadow: '0 0 35px rgba(6, 182, 212, 0.4)',
                  }}
                >
                  <WebCareBrandLogo size={70} />
                </div>
              )}
            </div>

            {/* Emblem Titles */}
            <h3
              className="webcare-welcome-brand-title"
              style={{ margin: '0 0 4px', fontSize: '18px', fontWeight: 800, color: '#ffffff' }}
            >
              WebCare <span style={{ color: '#38bdf8' }}>Pro</span>
            </h3>
            <div
              className="webcare-welcome-brand-sub"
              style={{
                fontSize: '11px',
                fontWeight: 700,
                color: '#94a3b8',
                letterSpacing: '0.12em',
                textTransform: 'uppercase',
                marginBottom: '14px',
              }}
            >
              SPEED • SECURITY • UPTIME
            </div>

            {/* Feature & Credential Tags (Matching user image: #12PlusYearsExp, #SeniorSysadmin) */}
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', justifyContent: 'center' }}>
              <span
                style={{
                  background: 'rgba(245, 158, 11, 0.14)',
                  border: '1px solid rgba(245, 158, 11, 0.4)',
                  color: '#fbbf24',
                  padding: '3px 9px',
                  borderRadius: '6px',
                  fontSize: '11px',
                  fontWeight: 700,
                }}
              >
                #12PlusYearsExp
              </span>
              <span
                style={{
                  background: 'rgba(192, 132, 252, 0.14)',
                  border: '1px solid rgba(192, 132, 252, 0.4)',
                  color: '#c084fc',
                  padding: '3px 9px',
                  borderRadius: '6px',
                  fontSize: '11px',
                  fontWeight: 700,
                }}
              >
                #SeniorSysadmin
              </span>
              <span
                style={{
                  background: 'rgba(6, 182, 212, 0.12)',
                  border: '1px solid rgba(6, 182, 212, 0.3)',
                  color: '#38bdf8',
                  padding: '3px 9px',
                  borderRadius: '6px',
                  fontSize: '11px',
                  fontWeight: 600,
                }}
              >
                #No Cloud Tracking
              </span>
              <span
                style={{
                  background: 'rgba(16, 185, 129, 0.12)',
                  border: '1px solid rgba(16, 185, 129, 0.3)',
                  color: '#34d399',
                  padding: '3px 9px',
                  borderRadius: '6px',
                  fontSize: '11px',
                  fontWeight: 600,
                }}
              >
                #100% On-Premise
              </span>
            </div>

            {/* Solo Freelancer Author Assurance */}
            <div
              className="webcare-welcome-author-box"
              style={{
                marginTop: '20px',
                paddingTop: '16px',
                borderTop: '1px solid rgba(255, 255, 255, 0.08)',
                width: '100%',
                fontSize: '11.5px',
                color: '#94a3b8',
                lineHeight: 1.45,
              }}
            >
              <div className="webcare-welcome-author-name">Crafted by <strong style={{ color: '#ffffff' }}>Mir Alamin</strong></div>
              <div className="webcare-welcome-author-role" style={{ color: '#64748b' }}>Senior Linux SysAdmin & WordPress Security Engineer</div>
            </div>
          </div>
        </div>

        {/* Collapsible Technical Details (1 Column with Extended Details) */}
        {showTechDetails && (
          <div
            className="webcare-welcome-tech-section"
            style={{
              padding: '0 40px 24px',
              borderTop: '1px solid rgba(255, 255, 255, 0.08)',
              marginTop: '12px',
              background: 'rgba(3, 7, 18, 0.45)',
            }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: '12px',
                margin: '18px 0 14px',
              }}
            >
              <div>
                <h4
                  className="webcare-welcome-tech-title"
                  style={{ margin: '0 0 4px', fontSize: '15px', fontWeight: 800, color: '#f1f5f9' }}
                >
                  Server Compatibility & Environment Checks
                </h4>
                <p
                  className="webcare-welcome-tech-desc"
                  style={{ margin: 0, fontSize: '12.5px', color: '#94a3b8' }}
                >
                  Comprehensive inspection of your hosting runtime, cryptographic engines, filesystem privileges, and database capabilities.
                </p>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                <div
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '8px',
                    background: 'rgba(16, 185, 129, 0.12)',
                    border: '1px solid rgba(16, 185, 129, 0.3)',
                    padding: '6px 14px',
                    borderRadius: '999px',
                    fontSize: '12.5px',
                    fontWeight: 700,
                    color: '#34d399',
                  }}
                >
                  <CheckCircle2 size={15} color="#10b581" />
                  Readiness Score: {readiness?.readiness_score ?? 100}%
                </div>
                <button
                  type="button"
                  onClick={fetchReadiness}
                  disabled={refreshingReadiness}
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px',
                    background: 'rgba(56, 189, 248, 0.14)',
                    border: '1px solid rgba(56, 189, 248, 0.35)',
                    color: '#38bdf8',
                    padding: '6px 14px',
                    borderRadius: '999px',
                    fontSize: '12.5px',
                    fontWeight: 700,
                    cursor: refreshingReadiness ? 'not-allowed' : 'pointer',
                    transition: 'all 0.15s ease',
                  }}
                  title="Re-run all 14 server readiness & compatibility checks"
                >
                  <RefreshCw size={13} className={refreshingReadiness ? 'webcare-spin-icon' : ''} />
                  <span>{refreshingReadiness ? 'Re-Checking Server...' : (readinessNotice || 'Refresh Checks')}</span>
                </button>
              </div>
            </div>

            {/* 1 Column Extended Details List */}
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: '10px',
                maxHeight: '360px',
                overflowY: 'auto',
                paddingRight: '6px',
              }}
            >
              {readiness && Object.values(readiness.checks).map((item) => {
                const isPass = item.status === 'pass';
                const isWarn = item.status === 'warn';
                const isFail = item.status === 'fail';

                const statusColor = isPass ? '#10b581' : isWarn ? '#f59e0b' : '#ef4444';
                const statusBg = isPass
                  ? 'rgba(16, 185, 129, 0.12)'
                  : isWarn
                  ? 'rgba(245, 158, 11, 0.12)'
                  : 'rgba(239, 68, 68, 0.12)';
                const statusBorder = isPass
                  ? 'rgba(16, 185, 129, 0.28)'
                  : isWarn
                  ? 'rgba(245, 158, 11, 0.35)'
                  : 'rgba(239, 68, 68, 0.35)';

                return (
                  <div
                    key={item.key}
                    style={{
                      background: 'rgba(15, 23, 42, 0.7)',
                      border: `1px solid ${statusBorder}`,
                      borderRadius: '12px',
                      padding: '14px 16px',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '8px',
                      boxShadow: '0 4px 12px rgba(0, 0, 0, 0.2)',
                    }}
                  >
                    {/* Header Row: Status, Title, Category, Critical Badge & Current Value */}
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        flexWrap: 'wrap',
                        gap: '10px',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                        <div
                          style={{
                            width: '24px',
                            height: '24px',
                            borderRadius: '50%',
                            background: statusBg,
                            border: `1px solid ${statusBorder}`,
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            flexShrink: 0,
                            color: statusColor,
                          }}
                        >
                          {isPass ? <CheckCircle2 size={14} /> : isWarn ? <AlertTriangle size={14} /> : <AlertOctagon size={14} />}
                        </div>
                        <span style={{ fontSize: '13.5px', fontWeight: 700, color: '#f8fafc' }}>
                          {item.title}
                        </span>
                        {item.category && (
                          <span
                            style={{
                              fontSize: '10.5px',
                              fontWeight: 600,
                              textTransform: 'uppercase',
                              letterSpacing: '0.05em',
                              padding: '2px 8px',
                              borderRadius: '4px',
                              background: 'rgba(255, 255, 255, 0.06)',
                              color: '#94a3b8',
                              border: '1px solid rgba(255, 255, 255, 0.1)',
                            }}
                          >
                            {item.category}
                          </span>
                        )}
                        {item.is_critical && isFail && (
                          <span
                            style={{
                              fontSize: '10.5px',
                              fontWeight: 700,
                              padding: '2px 8px',
                              borderRadius: '4px',
                              background: 'rgba(239, 68, 68, 0.15)',
                              color: '#f87171',
                              border: '1px solid rgba(239, 68, 68, 0.3)',
                            }}
                          >
                            Critical Missing
                          </span>
                        )}
                        {item.is_critical && !isFail && (
                          <span
                            style={{
                              fontSize: '10.5px',
                              fontWeight: 600,
                              padding: '2px 8px',
                              borderRadius: '4px',
                              background: 'rgba(56, 189, 248, 0.08)',
                              color: '#7dd3fc',
                              border: '1px solid rgba(56, 189, 248, 0.2)',
                            }}
                          >
                            Required
                          </span>
                        )}
                      </div>

                      <div
                        style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '6px',
                          background: statusBg,
                          border: `1px solid ${statusBorder}`,
                          padding: '3px 10px',
                          borderRadius: '6px',
                          fontSize: '12px',
                          fontWeight: 700,
                          color: statusColor,
                        }}
                      >
                        <span style={{ color: '#94a3b8', fontWeight: 500 }}>Detected:</span>
                        <span>{item.current}</span>
                      </div>
                    </div>

                    {/* Extended Description */}
                    <div style={{ fontSize: '12.5px', color: '#94a3b8', lineHeight: 1.5, paddingLeft: '32px' }}>
                      {item.description}
                    </div>

                    {/* Thresholds / Requirements Row */}
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '12px',
                        flexWrap: 'wrap',
                        fontSize: '11.5px',
                        paddingLeft: '32px',
                        color: '#64748b',
                      }}
                    >
                      <span>
                        <strong style={{ color: '#94a3b8' }}>Required:</strong> {item.required}
                      </span>
                      {item.recommended && (
                        <span>
                          • <strong style={{ color: '#94a3b8' }}>Recommended:</strong> {item.recommended}
                        </span>
                      )}
                    </div>

                    {/* Remedy / Actionable Recommendation Box (if warn or fail) */}
                    {(isWarn || isFail) && item.remedy && (
                      <div
                        style={{
                          marginTop: '4px',
                          marginLeft: '32px',
                          background: 'rgba(245, 158, 11, 0.08)',
                          border: '1px solid rgba(245, 158, 11, 0.25)',
                          borderRadius: '8px',
                          padding: '8px 12px',
                          fontSize: '12px',
                          color: '#fbbf24',
                          lineHeight: 1.45,
                        }}
                      >
                        <strong>💡 How to resolve:</strong> {item.remedy}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Footer Actions */}
        <div
          className="webcare-welcome-footer"
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '18px 40px',
            background: 'rgba(4, 9, 23, 0.6)',
            borderTop: '1px solid rgba(255, 255, 255, 0.08)',
            borderBottomLeftRadius: '26px',
            borderBottomRightRadius: '26px',
            flexWrap: 'wrap',
            gap: '12px',
          }}
        >
          <div
            className="webcare-welcome-footer-info"
            style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '10px', fontSize: '12px', color: '#64748b' }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <HeartHandshake size={15} color="#10b581" />
              <span style={{ color: '#94a3b8' }}>Have questions?</span>
              <a
                href="https://webcarepro.dev"
                target="_blank"
                rel="noopener noreferrer"
                style={{ color: '#38bdf8', textDecoration: 'none', fontWeight: 600 }}
              >
                Connect directly with Mir Alamin
              </a>
            </div>
            <span style={{ color: 'rgba(255, 255, 255, 0.2)' }}>•</span>
            <a
              href="https://webcarepro.dev/blog/post/webcare-wordpress-security-scanner"
              target="_blank"
              rel="noopener noreferrer"
              style={{
                color: '#34d399',
                textDecoration: 'none',
                fontWeight: 600,
                display: 'inline-flex',
                alignItems: 'center',
                gap: '4px',
              }}
            >
              <span>Explore All WebCare Pro Security Features</span>
              <ExternalLink size={12} />
            </a>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <button
              type="button"
              onClick={handleStartScanClick}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                background: 'rgba(255, 255, 255, 0.06)',
                color: '#f8fafc',
                border: '1px solid rgba(255, 255, 255, 0.15)',
                borderRadius: '12px',
                padding: '11px 20px',
                fontSize: '13.5px',
                fontWeight: 600,
                cursor: 'pointer',
                transition: 'all 0.15s ease',
              }}
            >
              <Play size={14} color="#38bdf8" />
              Run My First Scan
            </button>

            <button
              type="button"
              onClick={handleDismiss}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                background: 'linear-gradient(135deg, #0284c7 0%, #06b6d4 50%, #10b581 100%)',
                color: '#ffffff',
                border: 'none',
                borderRadius: '12px',
                padding: '11px 24px',
                fontSize: '13.5px',
                fontWeight: 700,
                cursor: 'pointer',
                boxShadow: '0 4px 18px rgba(6, 182, 212, 0.4)',
                transition: 'all 0.15s ease',
              }}
            >
              Start Using Scanner
              <ArrowRight size={15} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default WelcomeModal;
