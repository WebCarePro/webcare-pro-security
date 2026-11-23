import React, { useState, useEffect } from 'react';
import {
  X,
  Play,
  Save,
  Lock,
  HelpCircle,
  CheckSquare,
  Square,
  Sliders,
  CheckCircle2,
  Sparkles,
  ShieldCheck,
  RotateCcw,
  Info
} from 'lucide-react';

export interface CustomScanOptionDef {
  key: string;
  label: string;
  description: string;
  category: string;
  subtitle?: string;
  defaultChecked: boolean;
  engineTag: string;
  tagClass: 'pill-reputation' | 'pill-integrity' | 'pill-malware' | 'pill-database' | 'pill-vulnerability' | 'pill-system';
  highlightTerm?: string;
  highlightVariant?: 'variant-purple' | 'variant-emerald' | 'variant-amber';
}

export const CUSTOM_SCAN_OPTIONS_CATALOG: CustomScanOptionDef[] = [
  // 1-3. Reputation Checks (DNSBL, Google Safe Browsing, SURBL)
  {
    key: 'check_domain_blocklist',
    label: 'Check if this website is on a domain blocklist',
    subtitle: 'Reputation check',
    description: 'Queries Google Safe Browsing and major DNS blocklists (Spamhaus DBL, SURBL) to verify if your domain has been blacklisted due to malware, phishing, or abusive activities.',
    category: 'Reputation Checks',
    defaultChecked: true,
    engineTag: 'DNSBL Feed',
    tagClass: 'pill-reputation',
    highlightTerm: 'domain blocklist',
  },
  {
    key: 'check_spamvertised',
    label: 'Check if this website is being "Spamvertised"',
    subtitle: 'Reputation check',
    description: 'Checks global spam intelligence feeds (such as SURBL) to determine whether your domain is actively being advertised in unsolicited bulk phishing and spam campaigns.',
    category: 'Reputation Checks',
    defaultChecked: true,
    engineTag: 'SURBL Feed',
    tagClass: 'pill-reputation',
    highlightTerm: '"Spamvertised"',
    highlightVariant: 'variant-amber',
  },
  {
    key: 'check_spam_ip',
    label: 'Check if this website IP is generating spam',
    subtitle: 'Reputation check',
    description: 'Checks if your web server\'s outbound IP address is listed on major email spam and abusive IP databases (Spamhaus ZEN, CBL, UCEPROTECT).',
    category: 'Reputation Checks',
    defaultChecked: true,
    engineTag: 'IP Reputation',
    tagClass: 'pill-reputation',
    highlightTerm: 'generating spam',
  },

  // 4-23. General & Deep Detection Engines
  {
    key: 'scan_ip_detection',
    label: 'Scan for misconfigured visitor IP detection headers',
    description: 'Verifies whether your server correctly detects visitor IP addresses behind reverse proxies, Cloudflare, load balancers, or standard remote addresses, preventing header spoofing attacks.',
    category: 'General Options',
    defaultChecked: true,
    engineTag: 'Network Header',
    tagClass: 'pill-system',
    highlightTerm: 'visitor IP detection',
  },
  {
    key: 'scan_public_config',
    label: 'Scan for publicly accessible configuration, backup, or log files',
    description: 'Checks if critical files like .env, wp-config.php.bak, error logs (debug.log), or version control repositories (.git) are exposed to public web requests.',
    category: 'General Options',
    defaultChecked: true,
    engineTag: 'File Exposure',
    tagClass: 'pill-integrity',
    highlightTerm: 'configuration, backup, or log files',
    highlightVariant: 'variant-emerald',
  },
  {
    key: 'scan_public_quarantine',
    label: 'Scan for publicly accessible quarantined files',
    description: 'Verifies that quarantined files and the isolation directory are strictly protected from direct browser access via server configuration and .htaccess directives.',
    category: 'General Options',
    defaultChecked: true,
    engineTag: 'Vault Access',
    tagClass: 'pill-integrity',
    highlightTerm: 'quarantined files',
  },
  {
    key: 'scan_core_integrity',
    label: 'Scan core files against repository versions for changes',
    description: 'Compares every WordPress core file against the official WordPress.org cryptographic release checksums to detect tampered, injected, or modified core files.',
    category: 'General Options',
    defaultChecked: true,
    engineTag: 'Core SHA-256',
    tagClass: 'pill-integrity',
    highlightTerm: 'core files',
    highlightVariant: 'variant-emerald',
  },
  {
    key: 'scan_theme_integrity',
    label: 'Scan theme files against repository versions for changes',
    description: 'Verifies installed themes against official WordPress.org theme directory checksums to identify unauthorized code alterations and template injections.',
    category: 'General Options',
    defaultChecked: true,
    engineTag: 'Theme Checksum',
    tagClass: 'pill-integrity',
    highlightTerm: 'theme files',
  },
  {
    key: 'scan_plugin_integrity',
    label: 'Scan plugin files against repository versions for changes',
    description: 'Verifies installed plugins against official WordPress.org plugin directory checksums to identify modified plugin files and backdoor wrapper scripts.',
    category: 'General Options',
    defaultChecked: true,
    engineTag: 'Plugin Checksum',
    tagClass: 'pill-integrity',
    highlightTerm: 'plugin files',
  },
  {
    key: 'scan_unbundled_files',
    label: 'Scan wp-admin and wp-includes for files not bundled with WordPress',
    description: 'Detects unbundled, foreign, or orphaned PHP files lurking inside wp-admin and wp-includes that do not belong to the official WordPress distribution.',
    category: 'General Options',
    defaultChecked: true,
    engineTag: 'Orphan Files',
    tagClass: 'pill-integrity',
    highlightTerm: 'wp-admin and wp-includes',
    highlightVariant: 'variant-purple',
  },
  {
    key: 'scan_known_malware',
    label: 'Scan for signatures of known malicious files',
    description: 'Scans files against thousands of known malware, webshell (c99, r57, b374k, FilesMan), and PHP backdoor signatures.',
    category: 'General Options',
    defaultChecked: true,
    engineTag: 'Signature DB',
    tagClass: 'pill-malware',
    highlightTerm: 'known malicious files',
  },
  {
    key: 'scan_backdoors_heuristics',
    label: 'Scan file contents for backdoors, trojans and suspicious code',
    description: 'Uses an AST lexer and heuristic analysis to identify obfuscated PHP functions and trojan execution patterns.',
    category: 'General Options',
    defaultChecked: true,
    engineTag: 'AST Lexer',
    tagClass: 'pill-malware',
    highlightTerm: 'backdoors, trojans and suspicious code',
    highlightVariant: 'variant-purple',
  },
  {
    key: 'scan_malicious_urls',
    label: 'Scan file contents for malicious URLs',
    description: 'Inspects script files for malicious domains, phishing redirects, crypto-draining wallets, and command-and-control server endpoints.',
    category: 'General Options',
    defaultChecked: true,
    engineTag: 'URL Threat Intel',
    tagClass: 'pill-malware',
    highlightTerm: 'malicious URLs',
  },
  {
    key: 'scan_posts_content',
    label: 'Scan posts for known dangerous URLs and suspicious content',
    description: 'Audits published posts, pages, and drafts for injected hidden iframes, blackhat SEO spam links, pharmaceutical terms, and defacement scripts.',
    category: 'General Options',
    defaultChecked: true,
    engineTag: 'Post Content',
    tagClass: 'pill-database',
    highlightTerm: 'posts for known dangerous URLs',
    highlightVariant: 'variant-amber',
  },
  {
    key: 'scan_comments_content',
    label: 'Scan comments for known dangerous URLs and suspicious content',
    description: 'Scans pending and approved comments for dangerous URLs, phishing payloads, and automated spam injections.',
    category: 'General Options',
    defaultChecked: true,
    engineTag: 'Comment Spam',
    tagClass: 'pill-database',
    highlightTerm: 'comments',
  },
  {
    key: 'scan_options_content',
    label: 'Scan WordPress core, plugin, and theme options for known dangerous URLs and suspicious content',
    description: 'Audits the wp_options database table for serialized payload tampering, rogue JavaScript redirects in siteurl/home, and injected widget scripts.',
    category: 'General Options',
    defaultChecked: true,
    engineTag: 'wp_options DB',
    tagClass: 'pill-database',
    highlightTerm: 'plugin, and theme options',
    highlightVariant: 'variant-purple',
  },
  {
    key: 'scan_vulnerable_software',
    label: 'Scan for out of date, abandoned, and vulnerable plugins, themes, and WordPress versions',
    description: 'Audits all components against vulnerability feeds for known CVEs, unpatched security exploits, and abandoned software.',
    category: 'General Options',
    defaultChecked: true,
    engineTag: 'CVE Feed',
    tagClass: 'pill-vulnerability',
    highlightTerm: 'vulnerable plugins, themes',
    highlightVariant: 'variant-amber',
  },
  {
    key: 'scan_rogue_admins',
    label: 'Scan for suspicious admin users created outside of WordPress',
    description: 'Detects rogue administrator accounts created via direct database manipulation, SQL injection, or privilege escalation vulnerabilities.',
    category: 'General Options',
    defaultChecked: true,
    engineTag: 'User Forensics',
    tagClass: 'pill-database',
    highlightTerm: 'suspicious admin users',
    highlightVariant: 'variant-purple',
  },
  {
    key: 'scan_password_strength',
    label: 'Check the strength of passwords',
    description: 'Audits administrator and privileged user passwords against top dictionary attack wordlists and common password permutations.',
    category: 'General Options',
    defaultChecked: false, // Default unchecked matching screenshot
    engineTag: 'Credential Audit',
    tagClass: 'pill-database',
    highlightTerm: 'strength of passwords',
  },
  {
    key: 'monitor_disk_space',
    label: 'Monitor disk space',
    description: 'Monitors server storage space and inode exhaustion to prevent system crashes and log write halts during attacks.',
    category: 'General Options',
    defaultChecked: true,
    engineTag: 'Storage / Inodes',
    tagClass: 'pill-system',
    highlightTerm: 'disk space',
    highlightVariant: 'variant-emerald',
  },
  {
    key: 'monitor_firewall_status',
    label: 'Monitor Web Application Firewall status',
    description: 'Verifies that the Web Application Firewall (WAF) rules and virtual patching modules are fully initialized and actively intercepting attacks.',
    category: 'General Options',
    defaultChecked: true,
    engineTag: 'WAF Protection',
    tagClass: 'pill-system',
    highlightTerm: 'Web Application Firewall',
    highlightVariant: 'variant-emerald',
  },
  {
    key: 'scan_outside_root',
    label: 'Scan files outside your WordPress installation',
    description: 'Scans parent and adjacent web directories (when server permissions allow) for orphaned scripts and lateral movement files.',
    category: 'General Options',
    defaultChecked: true,
    engineTag: 'Filesystem Root',
    tagClass: 'pill-integrity',
    highlightTerm: 'outside your WordPress',
  },
  {
    key: 'scan_images_executable',
    label: 'Scan images, binary, and other files as if they were executable',
    description: 'Performs deep forensic inspection of uploaded media files (JPEG, PNG, GIF, SVG) to detect hidden PHP code and polyglot webshells embedded in EXIF metadata.',
    category: 'General Options',
    defaultChecked: true,
    engineTag: 'Polyglot EXIF',
    tagClass: 'pill-malware',
    highlightTerm: 'images, binary, and other files',
    highlightVariant: 'variant-amber',
  },
];

interface CustomScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  options: Record<string, boolean>;
  onOptionsChange: (newOptions: Record<string, boolean>) => void;
  onStartScan: (optionsToRun: Record<string, boolean>, saveAsDefault: boolean) => void;
  isScanning: boolean;
  onSavePreferences?: (optionsToSave: Record<string, boolean>) => Promise<void>;
}

export const CustomScanModal: React.FC<CustomScanModalProps> = ({
  isOpen,
  onClose,
  options,
  onOptionsChange,
  onStartScan,
  isScanning,
  onSavePreferences,
}) => {
  const [localOptions, setLocalOptions] = useState<Record<string, boolean>>(options);
  const [saveAsDefault, setSaveAsDefault] = useState<boolean>(true);
  const [activeTooltip, setActiveTooltip] = useState<string | null>(null);
  const [savingState, setSavingState] = useState<boolean>(false);
  const [saveMessage, setSaveMessage] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen) {
      setLocalOptions(options);
      setActiveTooltip(null);
      setSaveMessage(null);
    }
  }, [isOpen, options]);

  if (!isOpen) return null;

  const toggleOption = (key: string) => {
    setLocalOptions((prev) => ({
      ...prev,
      [key]: !prev[key],
    }));
  };

  const handleApplyPreset = (type: 'recommended' | 'all' | 'none' | 'malware' | 'database') => {
    const next: Record<string, boolean> = { ...localOptions };
    if (type === 'recommended') {
      CUSTOM_SCAN_OPTIONS_CATALOG.forEach((item) => {
        next[item.key] = item.defaultChecked;
      });
    } else if (type === 'all') {
      CUSTOM_SCAN_OPTIONS_CATALOG.forEach((item) => {
        next[item.key] = true;
      });
    } else if (type === 'none') {
      CUSTOM_SCAN_OPTIONS_CATALOG.forEach((item) => {
        next[item.key] = false;
      });
    } else if (type === 'malware') {
      CUSTOM_SCAN_OPTIONS_CATALOG.forEach((item) => {
        const isMalware = [
          'scan_known_malware',
          'scan_backdoors_heuristics',
          'scan_malicious_urls',
          'scan_images_executable',
          'scan_core_integrity',
          'scan_theme_integrity',
          'scan_plugin_integrity',
          'scan_unbundled_files',
        ].includes(item.key);
        next[item.key] = isMalware;
      });
    } else if (type === 'database') {
      CUSTOM_SCAN_OPTIONS_CATALOG.forEach((item) => {
        const isDb = [
          'scan_posts_content',
          'scan_comments_content',
          'scan_options_content',
          'scan_rogue_admins',
          'scan_password_strength',
        ].includes(item.key);
        next[item.key] = isDb;
      });
    }
    setLocalOptions(next);
  };

  const handleSaveOnly = async () => {
    setSavingState(true);
    setSaveMessage(null);
    try {
      onOptionsChange(localOptions);
      if (onSavePreferences) {
        await onSavePreferences(localOptions);
      }
      setSaveMessage('Custom scan preferences saved successfully!');
      setTimeout(() => setSaveMessage(null), 3000);
    } catch (e) {
      console.error(e);
      setSaveMessage('Error saving preferences.');
    } finally {
      setSavingState(false);
    }
  };

  const handleStartCustomScanClick = () => {
    onOptionsChange(localOptions);
    onStartScan(localOptions, saveAsDefault);
    onClose();
  };

  const activeCount = Object.entries(localOptions).filter(([k, v]) => Boolean(v)).length;
  const totalCount = CUSTOM_SCAN_OPTIONS_CATALOG.length;

  return (
    <div
      className="webcare-modal-backdrop webcare-custom-scan-backdrop"
      style={{
        zIndex: 9999999,
        position: 'fixed',
        inset: 0,
        background: 'rgba(9, 13, 22, 0.85)',
        backdropFilter: 'blur(10px)',
        WebkitBackdropFilter: 'blur(10px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '16px',
        overflowY: 'auto',
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget && !isScanning) {
          onClose();
        }
      }}
    >
      <div
        className="webcare-modal-window webcare-custom-scan-window"
        style={{
          width: '100%',
          maxWidth: '820px',
          maxHeight: '92vh',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
          animation: 'webcareFadeIn 0.2s ease-out',
        }}
      >
        {/* Modal Header */}
        <div
          className="webcare-custom-scan-header"
          style={{
            padding: '20px 24px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '16px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <div
              className="webcare-custom-scan-iconbox"
              style={{
                width: '42px',
                height: '42px',
                borderRadius: '10px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Sliders size={22} color="#0284c7" />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <h2 className="webcare-custom-scan-title" style={{ margin: 0, fontSize: '18px', fontWeight: 800, letterSpacing: '-0.3px' }}>
                  Custom Scan Engine Options
                </h2>
                <span className="webcare-custom-scan-active-pill">
                  {activeCount} of {totalCount} Active
                </span>
              </div>
              <p className="webcare-custom-scan-subtitle" style={{ margin: '4px 0 0 0', fontSize: '12px' }}>
                Select specific detection modules to tailor the audit scope to your site's security requirements.
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            disabled={isScanning}
            className="webcare-custom-scan-close-btn"
            style={{
              borderRadius: '8px',
              padding: '6px',
              cursor: isScanning ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              transition: 'all 0.15s ease',
            }}
            title="Close"
          >
            <X size={18} />
          </button>
        </div>

        {/* Preset Toolbar */}
        <div
          className="webcare-custom-scan-toolbar"
          style={{
            padding: '12px 24px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '8px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', fontWeight: 600 }}>
            <span className="webcare-custom-scan-toolbar-label">Presets:</span>
            <button
              type="button"
              onClick={() => handleApplyPreset('recommended')}
              className="webcare-custom-scan-preset-btn is-recommended"
            >
              Recommended (22)
            </button>
            <button
              type="button"
              onClick={() => handleApplyPreset('all')}
              className="webcare-custom-scan-preset-btn"
            >
              Select All
            </button>
            <button
              type="button"
              onClick={() => handleApplyPreset('none')}
              className="webcare-custom-scan-preset-btn"
            >
              Clear All
            </button>
            <button
              type="button"
              onClick={() => handleApplyPreset('malware')}
              className="webcare-custom-scan-preset-btn"
            >
              Malware & Integrity
            </button>
            <button
              type="button"
              onClick={() => handleApplyPreset('database')}
              className="webcare-custom-scan-preset-btn"
            >
              Database & Content
            </button>
          </div>

          {saveMessage && (
            <div style={{ fontSize: '11px', color: '#10b981', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '4px' }}>
              <CheckCircle2 size={13} /> {saveMessage}
            </div>
          )}
        </div>

        {/* Options List (Scrollable Area) */}
        <div
          className="webcare-custom-scan-scroll webcare-custom-scan-body"
          style={{
            padding: '16px 24px 24px',
            overflowY: 'auto',
            flex: 1,
            display: 'flex',
            flexDirection: 'column',
            gap: '12px',
          }}
        >
          {/* Section Heading: General Options (Wordfence Style) */}
          <div
            className="webcare-custom-scan-section-header"
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              paddingBottom: '8px',
              marginBottom: '4px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span className="webcare-custom-scan-section-title" style={{ fontSize: '14px', fontWeight: 800, letterSpacing: '0.2px' }}>
                General Options & Engine Suite
              </span>
              <span className="webcare-scan-engine-pill pill-system" style={{ fontSize: '10px' }}>
                {totalCount} Total Engines
              </span>
            </div>
            <span className="webcare-custom-scan-enabled-counter" style={{ fontSize: '12px', fontWeight: 600 }}>
              {activeCount} Enabled
            </span>
          </div>

          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              gap: '6px',
            }}
          >
            {CUSTOM_SCAN_OPTIONS_CATALOG.map((item) => {
              const isChecked = Boolean(localOptions[item.key]);
              const isTooltipOpen = activeTooltip === item.key;

              // Helper to highlight key term inside the label
              const renderHighlightedLabel = () => {
                if (!item.highlightTerm || !item.label.includes(item.highlightTerm)) {
                  return item.label;
                }
                const parts = item.label.split(item.highlightTerm);
                return (
                  <>
                    {parts[0]}
                    <span className={`webcare-scan-kw-highlight ${item.highlightVariant || ''}`}>
                      {item.highlightTerm}
                    </span>
                    {parts.slice(1).join(item.highlightTerm)}
                  </>
                );
              };

              return (
                <div
                  key={item.key}
                  className={`webcare-custom-scan-card ${isChecked ? 'is-active' : ''}`}
                  style={{
                    padding: '12px 16px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '6px',
                  }}
                >
                  <label
                    style={{
                      display: 'flex',
                      alignItems: 'flex-start',
                      justifyContent: 'space-between',
                      gap: '12px',
                      cursor: 'pointer',
                      userSelect: 'none',
                      margin: 0,
                    }}
                  >
                    {/* Left: Checkbox + Label */}
                    <div style={{ display: 'flex', alignItems: 'flex-start', gap: '14px', flex: 1 }}>
                      <div style={{ marginTop: '2px', display: 'flex', alignItems: 'center' }}>
                        <input
                          type="checkbox"
                          checked={isChecked}
                          onChange={(e) => {
                            e.stopPropagation();
                            toggleOption(item.key);
                          }}
                          className="webcare-custom-scan-checkbox"
                          style={{
                            width: '18px',
                            height: '18px',
                            cursor: 'pointer',
                            margin: 0,
                          }}
                        />
                      </div>

                      <div style={{ flex: 1 }}>
                        <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '8px', marginBottom: '2px' }}>
                          <span
                            className="webcare-custom-scan-card-label"
                            style={{
                              fontSize: '13px',
                              fontWeight: isChecked ? 600 : 500,
                              lineHeight: 1.4,
                            }}
                          >
                            {renderHighlightedLabel()}
                          </span>

                          {/* Engine Scope Tag Pill */}
                          <span className={`webcare-scan-engine-pill ${item.tagClass}`}>
                            {item.engineTag}
                          </span>

                          {/* Help / Tooltip Trigger (?) */}
                          <button
                            type="button"
                            onClick={(e) => {
                              e.preventDefault();
                              e.stopPropagation();
                              setActiveTooltip(isTooltipOpen ? null : item.key);
                            }}
                            className="webcare-custom-scan-help-btn"
                            style={{
                              background: 'none',
                              border: 'none',
                              padding: '2px',
                              cursor: 'pointer',
                              display: 'inline-flex',
                              alignItems: 'center',
                              lineHeight: 1,
                              transition: 'color 0.15s ease',
                            }}
                            title="Click for technical explanation"
                          >
                            <HelpCircle size={14} />
                          </button>
                        </div>

                        {item.subtitle && (
                          <div className="webcare-custom-scan-item-subtitle" style={{ fontSize: '11px', fontStyle: 'italic' }}>
                            {item.subtitle}
                          </div>
                        )}
                      </div>
                    </div>
                  </label>

                  {/* Inline Tooltip / Details Drawer */}
                  {isTooltipOpen && (
                    <div
                      className="webcare-custom-scan-tooltip-box"
                      style={{
                        marginLeft: '32px',
                        marginTop: '4px',
                        padding: '10px 14px',
                        borderRadius: '0 8px 8px 0',
                        fontSize: '12px',
                        lineHeight: 1.5,
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'flex-start', gap: '8px' }}>
                        <Info size={15} color="#0284c7" style={{ marginTop: '2px', flexShrink: 0 }} />
                        <div>{item.description}</div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Modal Footer Controls */}
        <div
          className="webcare-custom-scan-footer"
          style={{
            padding: '16px 24px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '12px',
          }}
        >
          {/* Left: Persist checkbox */}
          <label
            className="webcare-custom-scan-footer-label"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              fontSize: '12px',
              cursor: 'pointer',
              userSelect: 'none',
            }}
          >
            <input
              type="checkbox"
              checked={saveAsDefault}
              onChange={(e) => setSaveAsDefault(e.target.checked)}
              style={{ width: '15px', height: '15px', margin: 0, cursor: 'pointer' }}
            />
            <span>Save configuration as default profile</span>
          </label>

          {/* Right: Actions */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <button
              type="button"
              onClick={onClose}
              disabled={isScanning}
              className="webcare-custom-scan-btn-cancel"
              style={{
                borderRadius: '8px',
                padding: '8px 16px',
                fontSize: '12px',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              Cancel
            </button>

            {onSavePreferences && (
              <button
                type="button"
                onClick={handleSaveOnly}
                disabled={savingState || isScanning}
                className="webcare-custom-scan-btn-save"
                style={{
                  borderRadius: '8px',
                  padding: '8px 16px',
                  fontSize: '12px',
                  fontWeight: 600,
                  cursor: savingState || isScanning ? 'not-allowed' : 'pointer',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                <Save size={14} />
                <span>{savingState ? 'Saving...' : 'Save Preferences'}</span>
              </button>
            )}

            <button
              type="button"
              onClick={handleStartCustomScanClick}
              disabled={isScanning || activeCount === 0}
              className="webcare-custom-scan-btn-run"
              style={{
                borderRadius: '8px',
                padding: '8px 20px',
                fontSize: '13px',
                fontWeight: 700,
                color: '#ffffff',
                cursor: isScanning || activeCount === 0 ? 'not-allowed' : 'pointer',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                opacity: activeCount === 0 ? 0.6 : 1,
              }}
            >
              <Play size={15} fill="#ffffff" />
              <span>Run Custom Scan ({activeCount} Engines)</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
