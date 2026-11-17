import React, { useState, useEffect, Fragment } from 'react';
import { __ } from '@wordpress/i18n';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  User,
  Key,
  Lock,
  Eye,
  Copy,
  Check,
  ArrowUpRight,
  Edit3,
  ExternalLink,
  BookOpen,
  Database,
  Trash2,
  RotateCcw,
  RefreshCw,
  Archive,
  Search,
  X,
  ChevronDown,
  ChevronUp,
  Folder,
  Layers,
  Sparkles,
  FileText,
  Globe
} from 'lucide-react';
import { ComponentForensicsCard, SafeErrorBoundary, getFindingDisplayTitle } from '../App';

export interface FindingForensicsDrawerProps {
  issue: any;
  onOpenFileViewer?: (issue: any) => void;
  onOpenChangelog?: (issue: any) => void;
  onOpenPostViewer?: (issue: any) => void;
  onOpenDbInspector?: (issue: any) => void;
  onRemediateDbRow?: (issue: any, action: string) => void;
  onDeleteCronHook?: (issue: any) => void;
  onRemediateUser?: (issue: any, action: string, role?: string, targetAdminId?: number) => void;
  onDisableWpDebug?: (issue: any) => void;
  onCopyPath?: (path: string) => void;
  copiedPath?: string | null;
}

export const FindingForensicsDrawer: React.FC<FindingForensicsDrawerProps> = ({
  issue,
  onOpenFileViewer,
  onOpenChangelog,
  onOpenPostViewer,
  onOpenDbInspector,
  onRemediateDbRow,
  onDeleteCronHook,
  onRemediateUser,
  onDisableWpDebug,
  onCopyPath,
  copiedPath
}) => {
  const [showAllCaps, setShowAllCaps] = useState(false);
  const [capsSearch, setCapsSearch] = useState('');
  const [copiedSnippet, setCopiedSnippet] = useState(false);
  const [targetAdminId, setTargetAdminId] = useState<number | null>(null);
  const availableAdminOptions = Array.isArray(issue.admin_options)
    ? issue.admin_options.filter((admin: any) => Number.isSafeInteger(Number(admin?.id)) && Number(admin.id) > 0)
    : [];
  const selectedTargetAdminId = targetAdminId !== null &&
    availableAdminOptions.some((admin: any) => Number(admin.id) === targetAdminId)
    ? targetAdminId
    : null;

  useEffect(() => {
    setTargetAdminId(null);
  }, [issue.id]);

  // Type Identifiers
  const isUser = Boolean(
    issue.is_user ||
    issue.engine === 'wordpress-users' ||
    issue.type?.startsWith('user_') ||
    issue.type?.includes('user_capabilities') ||
    issue.type?.includes('admin_user') ||
    issue.type?.includes('weak_password') ||
    issue.type?.includes('app_password') ||
    issue.type?.includes('application_password') ||
    issue.type?.includes('generic_admin_username') ||
    issue.type?.includes('username_enumeration_risk') ||
    issue.file_path?.startsWith('user:') ||
    issue.file_path?.includes('_users:user_id_') ||
    issue.file_path?.includes('_usermeta:user_id_') ||
    issue.file_path?.includes('users.ID') ||
    issue.title?.toLowerCase().includes('app password') ||
    issue.display_title?.toLowerCase().includes('app password')
  );

  const isAppPasswordRisk = Boolean(
    issue.type?.includes('app_password') ||
    issue.type?.includes('application_password') ||
    issue.display_title?.toLowerCase().includes('app password') ||
    issue.title?.toLowerCase().includes('app password')
  );

  const rawUserId = issue.user_id ||
    (issue.file_path && issue.file_path.match(/user_id_(\d+)/i)?.[1]) ||
    (issue.file_path && issue.file_path.match(/user:\s*(\d+)/i)?.[1]) ||
    (issue.file_path && issue.file_path.match(/ID:\s*(\d+)/i)?.[1]) ||
    '';
  const parsedUserId = Number(rawUserId);
  const userId = Number.isInteger(parsedUserId) && parsedUserId > 0 ? parsedUserId : null;

  const isOrphanedAuthor = Boolean(
    issue.is_orphaned_author ||
    issue.type === 'orphaned_post_author' ||
    issue.file_path?.startsWith('author:')
  );

  const isComment = Boolean(
    issue.is_comment ||
    issue.engine === 'content-comments' ||
    (issue.file_path && issue.file_path.startsWith('comment:'))
  );
  const commentId = issue.comment_id || (issue.file_path && issue.file_path.match(/comment:\s*(\d+)/i)?.[1]) || '';
  const editCommentUrl = commentId ? `comment.php?action=editcomment&c=${commentId}` : 'edit-comments.php';

  const isPost = !isComment && Boolean(
    issue.is_post ||
    Boolean(issue.post_id) ||
    issue.engine === 'content-spam' ||
    issue.engine === 'content-posts' ||
    issue.engine === 'database-posts' ||
    (issue.file_path && issue.file_path.startsWith('post:'))
  );
  const postId = issue.post_id || (issue.file_path && issue.file_path.match(/post:\s*(\d+)/i)?.[1]) || '';
  const isPage = Boolean(issue.post_type === 'page' || (issue.file_path && issue.file_path.toLowerCase().includes('(page)')));
  const editPostUrl = issue.edit_url || (postId ? `post.php?post=${postId}&action=edit` : 'edit.php');

  const isCronHook = Boolean(
    issue.is_cron ||
    issue.type?.includes('cron') ||
    issue.engine === 'wordpress-cron' ||
    (issue.file_path && issue.file_path.startsWith('cron:'))
  );

  const isDbOption = Boolean(
    issue.engine === 'database-options' ||
    issue.file_path?.startsWith('wp_options:') ||
    issue.file_path?.startsWith('wp_options.') ||
    issue.type?.includes('option')
  );

  const isDbTable = !isUser && Boolean(
    issue.is_db_table ||
    issue.engine === 'database-table' ||
    isDbOption ||
    (issue.file_path && !issue.file_path.includes('/') && !issue.file_path.includes('\\') && (issue.file_path.includes('.') || issue.file_path.includes(' [ID:')))
  );

  const isDbRecord = !isUser && Boolean(
    isDbTable ||
    issue.engine === 'database-scanner' ||
    issue.engine === 'database-micro-anomaly' ||
    issue.file_path?.startsWith('db:') ||
    issue.file_path?.startsWith('table:')
  );

  const isComponent = Boolean(
    issue.is_dir ||
    issue.component_meta ||
    issue.engine === 'integrity-theme' ||
    issue.engine === 'integrity-plugin'
  );

  const isNonPhysical = Boolean(
    isCronHook ||
    isDbRecord ||
    isDbTable ||
    isDbOption ||
    isUser ||
    isPost ||
    isComment ||
    isOrphanedAuthor ||
    !issue.file_path ||
    issue.file_path.startsWith('cron:') ||
    issue.file_path.startsWith('wp_options:') ||
    issue.file_path.startsWith('wp_options.') ||
    issue.file_path.startsWith('db:') ||
    issue.file_path.startsWith('table:') ||
    issue.file_path.startsWith('user:') ||
    issue.file_path.startsWith('comment:') ||
    issue.file_path.startsWith('post:') ||
    issue.file_path.startsWith('hook:') ||
    issue.file_path.startsWith('author:') ||
    issue.file_path.includes(' [ID:') ||
    issue.file_path.includes('user_id_') ||
    issue.file_path.includes('_usermeta:') ||
    issue.file_path.includes('_users:') ||
    issue.engine === 'database-table' ||
    issue.engine === 'database-scanner' ||
    issue.engine === 'database-micro-anomaly' ||
    issue.engine === 'database-options' ||
    issue.engine === 'content-spam' ||
    issue.engine === 'content-comments' ||
    issue.engine === 'content-posts' ||
    issue.engine === 'wordpress-users' ||
    issue.engine === 'wordpress-cron'
  );

  const isPhysicalFile = !isNonPhysical && !issue.is_dir && (issue.file_path.includes('/') || issue.file_path.includes('\\') || issue.file_path.endsWith('.php'));

  const isCurrentUser = Boolean(
    issue.is_current_user ||
    (issue.user_id && (window as any).webcareScannerSettings?.currentUserId && issue.user_id === (window as any).webcareScannerSettings?.currentUserId)
  );

  const isWeakPassword = Boolean(
    issue.type === 'weak_password_detected' ||
    issue.type?.includes('weak_password')
  );

  const taintChain = Array.isArray(issue.taint_chain) && issue.taint_chain.length > 0
    ? issue.taint_chain
    : (issue.type === 'polymorphic_taint_webshell' && typeof issue.evidence === 'string' && issue.evidence.includes('➔'))
      ? issue.evidence.split('➔').map((s: string, idx: number) => {
          const clean = s.trim().replace(/^\[|\]$/g, '');
          const isSource = clean.toLowerCase().includes('source');
          const isSink = clean.toLowerCase().includes('sink');
          return {
            type: isSource ? 'source' : isSink ? 'sink' : 'propagation',
            description: clean,
            line: issue.line_number
          };
        })
      : null;

  const copyText = (text: string) => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text);
      setCopiedSnippet(true);
      setTimeout(() => setCopiedSnippet(false), 2000);
    }
  };

  // Plain-English Smart Recommendation
  const getSmartRecommendation = (): string => {
    if (issue.simple_action) return issue.simple_action;
    if (isOrphanedAuthor) {
      return 'The WordPress user account that authored this content was deleted without reassigning posts. Reassigning posts to an active administrator restores full author attribution and database consistency.';
    }
    if (issue.type === 'user_missing_capabilities') {
      return 'User account exists in the database but lacks standard role and capability metadata in usermeta. Review or assign a proper role in WP-Admin Users, or delete the ghost record if unauthorized.';
    }
    if (isWeakPassword) {
      const isPrivileged = issue.severity === 'critical' || issue.severity === 'high' || issue.display_title?.toLowerCase().includes('admin') || issue.display_title?.toLowerCase().includes('staff');
      if (isCurrentUser) {
        return 'Your logged-in account password matches a common or predictable dictionary pattern. Navigate to your WordPress profile to set a high-entropy passphrase or enroll a WebAuthn Passkey for instant brute-force immunity.';
      }
      if (isPrivileged) {
        return 'Administrator or privileged staff account password is weak or predictable. Navigate to WP-Admin Users to generate a strong passphrase or assign WebAuthn two-factor protection.';
      }
      return `User account ('${issue.user_login || 'user'}') password is weak or predictable. Update credentials in WP-Admin Users or encourage stronger passphrases to prevent credential stuffing.`;
    }
    if (isAppPasswordRisk || issue.type?.includes('app_password') || issue.type?.includes('application_password')) {
      return 'Privileged administrator account possesses an active Application Password that has never recorded usage. Review or revoke unused application passwords in WP-Admin > Users > Edit Profile.';
    }
    if (isUser) {
      return 'Review this WordPress user account configuration and role permissions in WP-Admin Users.';
    }
    if (issue.type === 'wp_debug_enabled' || (Boolean(issue.file_path && issue.file_path.endsWith('wp-config.php')) && (issue.type?.includes('debug') || issue.description?.includes('WP_DEBUG')))) {
      return 'WordPress debugging is enabled in production. Detailed errors, stack traces, and sensitive database configurations can be exposed to public visitors. 1-Click disable WP_DEBUG to lock down your configuration.';
    }
    if (issue.type === 'unsafe_permissions') {
      return 'World-writable permissions detected on server files. Enforce standard 0644 for files or 0755 for directories to prevent unauthorized local execution.';
    }
    if (issue.type?.includes('theme') || issue.engine === 'integrity-theme') {
      return 'Theme file differs from official WordPress.org cryptographic release. Revert clean code via Visual Diff or restore clean copy if this was not an intentional child theme change.';
    }
    if (issue.type?.includes('plugin') || issue.engine === 'integrity-plugin') {
      return 'Plugin file differs from official release checksum. Compare Visual Diff to inspect changes, or click Restore Clean Copy to revert to official repository code.';
    }
    if (issue.type?.includes('core') || issue.engine === 'integrity-core') {
      return 'WordPress core file integrity mismatch. Core files must never be modified directly. Click Restore Clean Copy to restore official WordPress core files.';
    }
    if (issue.type?.includes('unknown') || issue.type?.includes('webshell') || issue.type?.includes('backdoor') || issue.type?.includes('malware')) {
      return 'Unrecognized or standalone script in WordPress root directory. These scripts can be executed directly without authentication. Move to Safe Quarantine to encrypt and isolate.';
    }
    if (issue.type?.includes('dropin') || issue.file_path?.includes('object-cache.php')) {
      return 'Custom drop-in script detected. If you do not have an active persistent object cache service, deactivate or mark as trusted.';
    }
    if (isDbTable) {
      return 'Suspicious database option or serialized table row detected. Inspect row content to verify no rogue redirect URLs or persistent scripts are stored.';
    }
    if (isComment || isPost) {
      return 'Unsolicited spam link or unauthorized content injection detected. Moderate or delete this content to protect your site reputation and search ranking.';
    }
    return 'Review this security finding. If verified as benign or intentional, mark as Trusted Whitelist; otherwise, isolate with Safe Quarantine.';
  };

  // High-risk capabilities list for highlight
  const highRiskCaps = new Set([
    'manage_options',
    'install_plugins',
    'activate_plugins',
    'edit_plugins',
    'delete_plugins',
    'install_themes',
    'edit_themes',
    'switch_themes',
    'delete_themes',
    'edit_users',
    'create_users',
    'delete_users',
    'promote_users',
    'unfiltered_html',
    'edit_files',
    'export',
    'import',
    'update_core'
  ]);

  const allCapsList: string[] = issue.all_capabilities || [];
  const injectedCapsSet = new Set<string>(issue.injected_caps || []);
  const filteredCaps = capsSearch.trim()
    ? allCapsList.filter(c => c.toLowerCase().includes(capsSearch.toLowerCase().trim()))
    : allCapsList;

  const severityColor =
    issue.severity === 'critical' ? '#ef4444' :
    issue.severity === 'high' ? '#ea580c' :
    issue.severity === 'medium' ? '#d97706' : '#0284c7';

  return (
    <SafeErrorBoundary fallbackTitle="Security Finding Forensic Dossier Error">
      <div
        className="webcare-threat-expanded-dossier"
        style={{
          background: 'var(--webcare-bg-card, #ffffff)',
          border: '1px solid var(--webcare-border, #e2e8f0)',
          borderLeft: `4px solid ${severityColor}`,
          borderRadius: '14px',
          padding: '20px 24px',
          boxShadow: '0 4px 16px rgba(0, 0, 0, 0.04)',
          display: 'flex',
          flexDirection: 'column',
          gap: '16px',
          fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif'
        }}
      >
        {/* =========================================================
            HEADER & EXECUTIVE BRIEFING STRIP
            ========================================================= */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', marginBottom: '6px' }}>
              <span
                style={{
                  fontSize: '11px',
                  fontWeight: 800,
                  textTransform: 'uppercase',
                  letterSpacing: '0.06em',
                  padding: '3px 9px',
                  borderRadius: '6px',
                  background:
                    issue.severity === 'critical' ? '#fee2e2' :
                    issue.severity === 'high' ? '#ffedd5' :
                    issue.severity === 'medium' ? '#fef3c7' : '#e0f2fe',
                  color: severityColor,
                  border: `1px solid ${severityColor}40`
                }}
              >
                {issue.severity?.toUpperCase() || 'INFO'} THREAT
              </span>

              <span
                style={{
                  fontSize: '11px',
                  fontWeight: 700,
                  textTransform: 'uppercase',
                  letterSpacing: '0.04em',
                  padding: '3px 8px',
                  borderRadius: '6px',
                  background: 'var(--webcare-bg-surface, #f8fafc)',
                  color: 'var(--webcare-text-muted, #64748b)',
                  border: '1px solid var(--webcare-border, #cbd5e1)'
                }}
              >
                Engine: {issue.engine}
              </span>

              {issue.type && (
                <span style={{ fontSize: '12px', fontFamily: 'monospace', color: 'var(--webcare-text-secondary, #475569)', fontWeight: 600 }}>
                  vector: {issue.type}
                </span>
              )}
            </div>

            <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
              {getFindingDisplayTitle(issue)}
            </h3>
          </div>

          {/* Quick External Jump Links */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
            {isOrphanedAuthor ? (
              <a
                href={`edit.php?author=${(issue.file_path && issue.file_path.match(/author:\s*(\d+)/i)?.[1]) || issue.author_id || ''}`}
                target="_blank"
                rel="noopener noreferrer"
                className="webcare-btn"
                style={{
                  background: 'var(--webcare-bg-surface, #f8fafc)',
                  color: 'var(--webcare-primary, #4f46e5)',
                  border: '1px solid var(--webcare-border, #cbd5e1)',
                  fontSize: '12px',
                  padding: '5px 12px',
                  fontWeight: 600,
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '5px',
                  borderRadius: '7px'
                }}
                title="Open posts authored by this deleted user in WP-Admin"
              >
                <FileText size={12} />
                <span>View &amp; Reassign Posts</span>
                <ArrowUpRight size={11} />
              </a>
            ) : isUser ? (
              <a
                href={
                  isAppPasswordRisk
                    ? (userId ? `user-edit.php?user_id=${userId}#application-passwords-section` : 'users.php')
                    : (isCurrentUser ? (issue.profile_url || 'profile.php') : (issue.edit_url || (userId ? `user-edit.php?user_id=${userId}` : 'users.php')))
                }
                target="_blank"
                rel="noopener noreferrer"
                className="webcare-btn"
                style={{
                  background: 'var(--webcare-bg-surface, #f8fafc)',
                  color: 'var(--webcare-text-primary, #0f172a)',
                  border: '1px solid var(--webcare-border, #cbd5e1)',
                  fontSize: '12px',
                  padding: '5px 12px',
                  fontWeight: 600,
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '5px',
                  borderRadius: '7px'
                }}
                title={
                  isAppPasswordRisk
                    ? "Manage or revoke application passwords in WordPress User Editor"
                    : (isCurrentUser ? "Open your WordPress Profile" : "Open WordPress User Editor")
                }
              >
                <Edit3 size={12} />
                <span>
                  {isAppPasswordRisk
                    ? 'Manage App Passwords ↗'
                    : (isCurrentUser ? 'My Profile' : (issue.type === 'user_missing_capabilities' ? 'Review Account' : 'Edit in WP-Admin'))}
                </span>
                <ArrowUpRight size={11} />
              </a>
            ) : isPost ? (
              <a
                href={editPostUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="webcare-btn"
                style={{
                  background: 'var(--webcare-bg-surface, #f8fafc)',
                  color: 'var(--webcare-primary, #4f46e5)',
                  border: '1px solid var(--webcare-border, #cbd5e1)',
                  fontSize: '12px',
                  padding: '5px 12px',
                  fontWeight: 600,
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '5px',
                  borderRadius: '7px'
                }}
                title={isPage ? `Open WordPress page editor for #${postId}` : `Open WordPress post editor for #${postId}`}
              >
                <Edit3 size={12} />
                <span>{isPage ? 'Edit Page in WP-Admin' : 'Edit Post in WP-Admin'}</span>
                <ArrowUpRight size={11} />
              </a>
            ) : (isDbTable || isDbRecord) ? (
              onOpenDbInspector && (
                <button
                  type="button"
                  className="webcare-btn"
                  style={{
                    background: 'var(--webcare-bg-surface, #f8fafc)',
                    color: '#7e22ce',
                    border: '1px solid #e9d5ff',
                    fontSize: '12px',
                    padding: '5px 12px',
                    fontWeight: 600,
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '5px',
                    borderRadius: '7px',
                    cursor: 'pointer'
                  }}
                  onClick={() => onOpenDbInspector(issue)}
                  title="Inspect complete database row data and columns"
                >
                  <Database size={12} />
                  <span>Inspect DB Row</span>
                </button>
              )
            ) : null}

            {isPhysicalFile && !issue.is_dir && onOpenFileViewer && (
              <button
                type="button"
                className="webcare-btn"
                style={{
                  background: 'var(--webcare-bg-surface, #f8fafc)',
                  color: 'var(--webcare-primary, #4f46e5)',
                  border: '1px solid rgba(79, 70, 229, 0.3)',
                  fontSize: '12px',
                  padding: '5px 12px',
                  fontWeight: 600,
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '5px',
                  borderRadius: '7px',
                  cursor: 'pointer'
                }}
                onClick={() => onOpenFileViewer(issue)}
              >
                <Eye size={12} />
                <span>Inspect Source Code</span>
              </button>
            )}
          </div>
        </div>

        {/* =========================================================
            PLAIN-ENGLISH SECURITY IMPACT & RECOMMENDATION STRIP
            ========================================================= */}
        <div
          style={{
            display: 'flex',
            alignItems: 'flex-start',
            gap: '12px',
            padding: '14px 16px',
            borderRadius: '10px',
            background:
              issue.severity === 'critical' ? 'rgba(239, 68, 68, 0.04)' :
              issue.severity === 'high' ? 'rgba(249, 115, 22, 0.04)' : 'rgba(99, 102, 241, 0.04)',
            border: `1px solid ${severityColor}25`,
            lineHeight: 1.55
          }}
        >
          <div
            style={{
              width: '32px',
              height: '32px',
              borderRadius: '8px',
              background: `${severityColor}15`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
              marginTop: '1px'
            }}
          >
            <ShieldAlert size={16} color={severityColor} />
          </div>

          <div style={{ flex: 1, minWidth: 0, fontSize: '13px' }}>
            <div style={{ fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '3px' }}>
              Incident Overview:
            </div>
            <div style={{ color: 'var(--webcare-text-secondary, #475569)', marginBottom: '8px' }}>
              {issue.description}
            </div>

            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '6px', fontSize: '12.5px', color: 'var(--webcare-text-primary, #0f172a)' }}>
              <span style={{ fontSize: '14px', lineHeight: 1 }}>💡</span>
              <div>
                <strong style={{ color: severityColor }}>Recommended Mitigation: </strong>
                <span>{getSmartRecommendation()}</span>
              </div>
            </div>
          </div>
        </div>

        {/* =========================================================
            USER & IDENTITY FORENSICS SECTION (WHEN USER / PASS FINDING)
            ========================================================= */}
        {isUser && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            
            {/* Current Logged-in Administrator Advisory */}
            {isCurrentUser && (
              <div
                style={{
                  background: 'linear-gradient(135deg, rgba(245, 158, 11, 0.08) 0%, rgba(217, 119, 6, 0.12) 100%)',
                  border: '1px solid rgba(245, 158, 11, 0.35)',
                  borderRadius: '10px',
                  padding: '14px 18px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  flexWrap: 'wrap',
                  gap: '12px'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: 1, minWidth: '280px' }}>
                  <div
                    style={{
                      width: '38px',
                      height: '38px',
                      borderRadius: '8px',
                      background: 'rgba(245, 158, 11, 0.2)',
                      border: '1px solid rgba(245, 158, 11, 0.4)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      flexShrink: 0
                    }}
                  >
                    <Key size={18} color="#d97706" />
                  </div>
                  <div>
                    <div style={{ fontSize: '13px', fontWeight: 700, color: '#b45309' }}>
                      Current Logged-in Administrator Account
                    </div>
                    <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px', lineHeight: 1.45 }}>
                      You are currently authenticated as this administrator. Account demotion and deletion are safely prevented to keep you from being locked out. <strong>Please update your password immediately in your user profile</strong> to secure your website against brute-force attacks.
                    </div>
                  </div>
                </div>

                <a
                  href={issue.password_url || 'profile.php#password'}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="webcare-btn"
                  style={{
                    background: '#dc2626',
                    color: '#ffffff',
                    border: 'none',
                    fontSize: '12px',
                    padding: '8px 16px',
                    fontWeight: 700,
                    borderRadius: '8px',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px',
                    textDecoration: 'none',
                    cursor: 'pointer',
                    boxShadow: '0 2px 6px rgba(220, 38, 38, 0.35)'
                  }}
                  title="Open WordPress profile to change password immediately"
                >
                  <Key size={13} color="#ffffff" />
                  <span>Change Password in Profile</span>
                  <ArrowUpRight size={11} />
                </a>
              </div>
            )}

            {/* WordPress Debugging Lockdown Remediation Box */}
            {(issue.type === 'wp_debug_enabled' || (Boolean(issue.file_path && issue.file_path.endsWith('wp-config.php')) && (issue.type?.includes('debug') || issue.description?.includes('WP_DEBUG')))) && (
              <div
                style={{
                  background: 'rgba(5, 150, 105, 0.05)',
                  border: '1px solid rgba(5, 150, 105, 0.25)',
                  borderRadius: '10px',
                  padding: '14px 18px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  flexWrap: 'wrap',
                  gap: '12px'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: 1, minWidth: '280px' }}>
                  <div
                    style={{
                      width: '38px',
                      height: '38px',
                      borderRadius: '8px',
                      background: 'rgba(5, 150, 105, 0.12)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      flexShrink: 0
                    }}
                  >
                    <ShieldCheck size={18} color="#059669" />
                  </div>
                  <div>
                    <div style={{ fontSize: '13px', fontWeight: 700, color: '#047857' }}>
                      Production Hardening: WP_DEBUG is Active
                    </div>
                    <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px', lineHeight: 1.45 }}>
                      Live error output exposes server file paths, SQL queries, and potential credentials to visitors. 1-Click disable comments out debug blocks, sets <code>WP_DEBUG</code>, <code>WP_DEBUG_LOG</code>, and <code>WP_DEBUG_DISPLAY</code> to <code>false</code>, silences <code>display_errors</code>, and creates an encrypted rollback backup.
                    </div>
                  </div>
                </div>

                {issue.status === 'open' && onDisableWpDebug && (
                  <button
                    type="button"
                    className="webcare-btn"
                    style={{
                      background: 'linear-gradient(135deg, #059669 0%, #047857 100%)',
                      color: '#ffffff',
                      border: '1px solid #047857',
                      padding: '8px 16px',
                      borderRadius: '7px',
                      fontSize: '12.5px',
                      fontWeight: 700,
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '6px',
                      cursor: 'pointer',
                      boxShadow: '0 2px 4px rgba(5, 150, 105, 0.25)'
                    }}
                    onClick={() => onDisableWpDebug(issue)}
                  >
                    <ShieldCheck size={14} />
                    <span>Disable WordPress Debugging</span>
                  </button>
                )}
              </div>
            )}

            {/* Orphaned Author Remediation Box */}
            {isOrphanedAuthor && (
              <div
                style={{
                  background: 'rgba(79, 70, 229, 0.05)',
                  border: '1px solid rgba(79, 70, 229, 0.25)',
                  borderRadius: '10px',
                  padding: '14px 18px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  flexWrap: 'wrap',
                  gap: '12px'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: 1, minWidth: '280px' }}>
                  <div
                    style={{
                      width: '38px',
                      height: '38px',
                      borderRadius: '8px',
                      background: 'rgba(79, 70, 229, 0.12)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      flexShrink: 0
                    }}
                  >
                    <FileText size={18} color="#4f46e5" />
                  </div>
                  <div>
                    <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-primary, #4f46e5)' }}>
                      Deleted User Account — Orphaned Posts Detected
                    </div>
                    <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px', lineHeight: 1.45 }}>
                      The author account for these posts no longer exists in WordPress. Reassign attribution to an active administrator or editor to restore editorial integrity.
                    </div>
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                  <label htmlFor={'webcare-reassign-admin-' + issue.id} className="screen-reader-text">
                    {__('Select an administrator to receive these posts', 'webcare-pro-security')}
                  </label>
                  <select
                    id={'webcare-reassign-admin-' + issue.id}
                    className="webcare-firewall-input"
                    value={selectedTargetAdminId ?? ''}
                    onChange={(event) => {
                      const selectedId = Number(event.currentTarget.value);
                      setTargetAdminId(
                        Number.isSafeInteger(selectedId) &&
                        availableAdminOptions.some((admin: any) => Number(admin.id) === selectedId)
                          ? selectedId
                          : null
                      );
                    }}
                    aria-label={__('Select an administrator to receive these posts', 'webcare-pro-security')}
                  >
                    <option value="">{__('Select an administrator', 'webcare-pro-security')}</option>
                    {availableAdminOptions.map((admin: any) => (
                      <option key={Number(admin.id)} value={Number(admin.id)}>
                        {(admin.display_name || admin.user_login || __('Administrator', 'webcare-pro-security')) + ' (#' + Number(admin.id) + ')'}
                      </option>
                    ))}
                  </select>
                  <button
                    type="button"
                    className="webcare-btn-micro webcare-action-btn-clean"
                    disabled={selectedTargetAdminId === null || !onRemediateUser}
                    onClick={() => {
                      if (selectedTargetAdminId !== null) {
                        onRemediateUser?.(issue, 'reassign_orphaned_posts', undefined, selectedTargetAdminId);
                      }
                    }}
                    title={__('Reassign orphaned posts to the selected administrator', 'webcare-pro-security')}
                  >
                    <RotateCcw size={12} />
                    <span>{__('Reassign Posts', 'webcare-pro-security')}</span>
                  </button>
                </div>

                <a
                  href={`edit.php?author=${(issue.file_path && issue.file_path.match(/author:\s*(\d+)/i)?.[1]) || issue.author_id || ''}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="webcare-btn"
                  style={{
                    background: '#4f46e5',
                    color: '#ffffff',
                    border: 'none',
                    fontSize: '12px',
                    padding: '8px 16px',
                    fontWeight: 700,
                    borderRadius: '8px',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px',
                    textDecoration: 'none'
                  }}
                >
                  <FileText size={13} color="#ffffff" />
                  <span>{__('View Posts in WP-Admin', 'webcare-pro-security')}</span>
                  <ArrowUpRight size={11} />
                </a>
              </div>
            )}

            {/* Non-current user weak password warning */}
            {!isCurrentUser && isWeakPassword && (
              <div
                style={{
                  background: 'rgba(239, 68, 68, 0.07)',
                  border: '1px solid rgba(239, 68, 68, 0.3)',
                  borderRadius: '10px',
                  padding: '14px 18px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  flexWrap: 'wrap',
                  gap: '12px'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: 1, minWidth: '280px' }}>
                  <div
                    style={{
                      width: '38px',
                      height: '38px',
                      borderRadius: '8px',
                      background: 'rgba(239, 68, 68, 0.15)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      flexShrink: 0
                    }}
                  >
                    <Key size={18} color="#ef4444" />
                  </div>
                  <div>
                    <div style={{ fontSize: '13px', fontWeight: 700, color: '#dc2626' }}>
                      Weak or Dictionary Password Detected
                    </div>
                    <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px', lineHeight: 1.45 }}>
                      This account is using a weak or predictable password matching common wordlists or username permutations. Update the user password to a high-entropy passphrase.
                    </div>
                  </div>
                </div>

                <a
                  href={issue.password_url || (issue.edit_url ? `${issue.edit_url}#password` : (userId ? `user-edit.php?user_id=${userId}#password` : 'users.php'))}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="webcare-btn"
                  style={{
                    background: '#dc2626',
                    color: '#ffffff',
                    border: 'none',
                    fontSize: '12px',
                    padding: '8px 16px',
                    fontWeight: 700,
                    borderRadius: '8px',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px',
                    textDecoration: 'none'
                  }}
                >
                  <Key size={13} color="#ffffff" />
                  <span>Change User Password</span>
                  <ArrowUpRight size={11} />
                </a>
              </div>
            )}

            {/* Injected capabilities warning */}
            {issue.injected_caps && issue.injected_caps.length > 0 && (
              <div
                style={{
                  background: 'rgba(239, 68, 68, 0.08)',
                  border: '1px solid rgba(239, 68, 68, 0.25)',
                  borderRadius: '10px',
                  padding: '14px 16px'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12.5px', fontWeight: 700, color: '#dc2626', marginBottom: '8px' }}>
                  <AlertTriangle size={15} color="#dc2626" />
                  <span>Stealth Injected Capabilities Detected ({issue.injected_caps.length}):</span>
                </div>
                <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginBottom: '8px' }}>
                  {issue.injected_caps.map((cap: string) => (
                    <span
                      key={cap}
                      style={{
                        background: '#fee2e2',
                        color: '#991b1b',
                        border: '1px solid #fca5a5',
                        padding: '2px 8px',
                        borderRadius: '4px',
                        fontSize: '11px',
                        fontWeight: 700,
                        fontFamily: 'monospace'
                      }}
                    >
                      {cap}
                    </span>
                  ))}
                </div>
                <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.5 }}>
                  These permissions were directly injected into <code>wp_usermeta</code> (via a malicious plugin or direct database tampering) and do not belong to the standard role.
                </div>
              </div>
            )}

            {/* Credential & Posture Executive Scorecard Grid */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
                gap: '10px',
                padding: '14px',
                background: 'var(--webcare-bg-surface, #f8fafc)',
                border: '1px solid var(--webcare-border, #e2e8f0)',
                borderRadius: '10px'
              }}
            >
              {/* Username */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                <span style={{ fontSize: '10.5px', fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  Username / Login
                </span>
                <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)', fontFamily: 'monospace' }}>
                  {issue.user_login || issue.user_display_name || '(Unknown)'}
                </span>
              </div>

              {/* User ID */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                <span style={{ fontSize: '10.5px', fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  User ID
                </span>
                <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                  {userId ? `#${userId}` : (issue.user_id ? `#${issue.user_id}` : 'N/A')}
                </span>
              </div>

              {/* Declared Role(s) */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                <span style={{ fontSize: '10.5px', fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  Declared Role(s)
                </span>
                <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap', alignItems: 'center' }}>
                  {(() => {
                    const rolesList: string[] = issue.user_roles_list && issue.user_roles_list.length > 0
                      ? issue.user_roles_list
                      : issue.user_roles && issue.user_roles !== 'none'
                      ? issue.user_roles.split(',').map((r: string) => r.trim())
                      : ['administrator'];

                    return rolesList.map((r: string) => {
                      const isAdmin = r.toLowerCase().includes('admin');
                      return (
                        <span
                          key={r}
                          style={{
                            background: isAdmin ? '#fee2e2' : '#e0f2fe',
                            color: isAdmin ? '#b91c1c' : '#0369a1',
                            border: `1px solid ${isAdmin ? '#fca5a5' : '#bae6fd'}`,
                            padding: '2px 7px',
                            borderRadius: '4px',
                            fontSize: '10.5px',
                            fontWeight: 700,
                            textTransform: 'uppercase'
                          }}
                        >
                          {r}
                        </span>
                      );
                    });
                  })()}
                </div>
              </div>

              {/* Email Address */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                <span style={{ fontSize: '10.5px', fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  Email Address
                </span>
                <span style={{ fontSize: '12px', color: 'var(--webcare-primary, #4f46e5)', wordBreak: 'break-all' }}>
                  {issue.user_email || '(Not available)'}
                </span>
              </div>

              {/* Registered Date */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                <span style={{ fontSize: '10.5px', fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  Registered Date
                </span>
                <span style={{ fontSize: '12px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                  {issue.user_registered || '(Not recorded)'}
                </span>
              </div>

              {/* User Level */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                <span style={{ fontSize: '10.5px', fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  User Level (wp_user_level)
                </span>
                <span style={{ fontSize: '12px', fontWeight: 700, color: (issue.user_level ?? 0) >= 7 ? '#dc2626' : 'var(--webcare-text-primary, #0f172a)' }}>
                  Level {issue.user_level ?? 10} {(issue.user_level ?? 10) >= 8 ? '(Admin Tier)' : '(Standard)'}
                </span>
              </div>

              {/* Authored Posts */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                <span style={{ fontSize: '10.5px', fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  Authored Posts
                </span>
                <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                  {issue.authored_posts_count ?? 1} published posts
                </span>
              </div>

              {/* Password Hash Engine */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                <span style={{ fontSize: '10.5px', fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  Password Hash Engine
                </span>
                <span style={{ fontSize: '11.5px', fontFamily: 'monospace', color: issue.hash_type?.includes('MD5') ? '#dc2626' : '#0284c7', fontWeight: 600 }}>
                  {issue.hash_type || 'Standard Hash'}
                </span>
              </div>

              {/* Two-Factor Status */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                <span style={{ fontSize: '10.5px', fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  Two-Factor (2FA) Status
                </span>
                <div style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '12px' }}>
                  {issue.two_factor_enabled ? (
                    <span style={{ color: '#047857', fontWeight: 700, display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                      <Check size={12} color="#10b981" /> Protected (Active)
                    </span>
                  ) : (
                    <span style={{ color: '#dc2626', fontWeight: 700, display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                      <AlertTriangle size={12} color="#dc2626" /> Not Enabled
                    </span>
                  )}
                </div>
              </div>
            </div>

            {/* All Assigned Capabilities Matrix Accordion */}
            {allCapsList.length > 0 && (
              <div
                style={{
                  background: 'var(--webcare-bg-surface, #f8fafc)',
                  border: '1px solid var(--webcare-border, #e2e8f0)',
                  borderRadius: '10px',
                  overflow: 'hidden'
                }}
              >
                <div
                  style={{
                    padding: '12px 16px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    cursor: 'pointer',
                    userSelect: 'none'
                  }}
                  onClick={() => setShowAllCaps(!showAllCaps)}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Lock size={15} color="#4f46e5" />
                    <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                      All Assigned Capabilities & Permissions Matrix
                    </span>
                    <span
                      style={{
                        fontSize: '11px',
                        fontWeight: 700,
                        padding: '2px 8px',
                        borderRadius: '999px',
                        background: 'rgba(99, 102, 241, 0.12)',
                        color: '#4f46e5'
                      }}
                    >
                      {issue.capabilities_count || allCapsList.length} Active Capabilities
                    </span>
                  </div>

                  <button
                    type="button"
                    style={{
                      background: 'none',
                      border: 'none',
                      cursor: 'pointer',
                      color: 'var(--webcare-primary, #4f46e5)',
                      fontSize: '12px',
                      fontWeight: 600,
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '4px'
                    }}
                  >
                    <span>{showAllCaps ? 'Hide Capabilities' : 'Inspect All Capabilities'}</span>
                    {showAllCaps ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                  </button>
                </div>

                {showAllCaps && (
                  <div style={{ padding: '14px 16px', borderTop: '1px solid var(--webcare-border, #e2e8f0)', display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    {/* Live Capabilities Filter Input */}
                    <div style={{ position: 'relative' }}>
                      <Search size={13} color="#94a3b8" style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)' }} />
                      <input
                        type="text"
                        placeholder="Filter capabilities (e.g. edit_posts, manage_options)..."
                        value={capsSearch}
                        onChange={(e) => setCapsSearch(e.target.value)}
                        style={{
                          width: '100%',
                          fontSize: '12px',
                          padding: '6px 10px 6px 30px',
                          borderRadius: '6px',
                          border: '1px solid var(--webcare-border, #cbd5e1)',
                          background: 'var(--webcare-bg-card, #ffffff)',
                          color: 'var(--webcare-text-primary, #0f172a)',
                          outline: 'none'
                        }}
                      />
                    </div>

                    <div
                      style={{
                        display: 'flex',
                        flexWrap: 'wrap',
                        gap: '6px',
                        maxHeight: '220px',
                        overflowY: 'auto',
                        padding: '10px',
                        background: 'var(--webcare-bg-card, #ffffff)',
                        borderRadius: '6px',
                        border: '1px solid var(--webcare-border, #e2e8f0)'
                      }}
                    >
                      {filteredCaps.map((cap) => {
                        const isInjected = injectedCapsSet.has(cap);
                        const isDangerous = highRiskCaps.has(cap);

                        return (
                          <span
                            key={cap}
                            style={{
                              fontSize: '11px',
                              fontFamily: 'monospace',
                              padding: '2px 7px',
                              borderRadius: '4px',
                              border: '1px solid',
                              fontWeight: isDangerous || isInjected ? 700 : 500,
                              background: isInjected ? '#ffedd5' : isDangerous ? '#fee2e2' : 'var(--webcare-bg-surface, #f8fafc)',
                              color: isInjected ? '#c2410c' : isDangerous ? '#b91c1c' : 'var(--webcare-text-secondary, #475569)',
                              borderColor: isInjected ? '#fed7aa' : isDangerous ? '#fca5a5' : 'var(--webcare-border, #cbd5e1)'
                            }}
                          >
                            {cap}
                          </span>
                        );
                      })}
                      {filteredCaps.length === 0 && (
                        <span style={{ fontSize: '12px', color: '#94a3b8', fontStyle: 'italic' }}>
                          No capabilities matched &quot;{capsSearch}&quot;
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* =========================================================
            COMPONENT / THEME / PLUGIN FORENSICS
            ========================================================= */}
        {isComponent && onOpenChangelog && (
          <ComponentForensicsCard
            issue={issue}
            onOpenChangelog={onOpenChangelog}
            onCopyPath={onCopyPath || copyText}
            copiedPath={copiedPath || null}
          />
        )}

        {/* =========================================================
            DATABASE RECORD FORENSICS
            ========================================================= */}
        {isDbTable && (
          <div
            style={{
              padding: '14px 16px',
              borderRadius: '10px',
              background: 'var(--webcare-bg-surface, #f8fafc)',
              border: '1px solid var(--webcare-border, #e2e8f0)',
              display: 'flex',
              flexDirection: 'column',
              gap: '10px'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
              <div>
                <span style={{ fontSize: '11px', fontWeight: 700, color: '#9d174d', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  Database Record Forensics
                </span>
                <div style={{ fontSize: '13.5px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)', marginTop: '2px' }}>
                  Table: <code style={{ color: '#9d174d' }}>{issue.table_name || issue.file_path}</code>
                  {issue.column_name && <span> &bull; Column: <code>{issue.column_name}</code></span>}
                  {issue.row_id && <span> &bull; Row ID: <strong>#{issue.row_id}</strong></span>}
                </div>
              </div>

              <div style={{ display: 'flex', gap: '8px' }}>
                {onOpenDbInspector && (
                  <button
                    type="button"
                    className="webcare-btn"
                    style={{ fontSize: '12px', fontWeight: 600 }}
                    onClick={() => onOpenDbInspector(issue)}
                  >
                    <Database size={13} /> Inspect Row
                  </button>
                )}
                {onRemediateDbRow && (
                  <button
                    type="button"
                    className="webcare-btn"
                    style={{ background: '#fef2f2', color: '#dc2626', border: '1px solid #fecaca', fontSize: '12px', fontWeight: 600 }}
                    onClick={() => onRemediateDbRow(issue, 'delete_row')}
                  >
                    <Trash2 size={13} /> Delete Row (Auto-Backup)
                  </button>
                )}
              </div>
            </div>
          </div>
        )}

        {/* =========================================================
            CODE SNIPPET & TECHNICAL EVIDENCE
            ========================================================= */}
        {(issue.code_snippet || issue.comment_content) && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-secondary, #475569)' }}>
                Detected Code Snippet / Signature {issue.line_number ? `(Line #${issue.line_number})` : ''}:
              </span>
              <button
                type="button"
                className="webcare-btn"
                style={{
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  fontSize: '11px',
                  color: copiedSnippet ? '#16a34a' : 'var(--webcare-text-muted, #64748b)',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '4px'
                }}
                onClick={() => copyText(issue.code_snippet || issue.comment_content || '')}
              >
                {copiedSnippet ? <Check size={12} color="#16a34a" /> : <Copy size={12} />}
                <span>{copiedSnippet ? 'Copied' : 'Copy Snippet'}</span>
              </button>
            </div>

            <pre
              style={{
                margin: 0,
                padding: '12px 14px',
                borderRadius: '8px',
                background: '#090d16',
                color: '#38bdf8',
                fontSize: '12px',
                fontFamily: 'monospace',
                overflowX: 'auto',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-all',
                maxHeight: '220px',
                border: '1px solid rgba(255, 255, 255, 0.1)'
              }}
            >
              {issue.code_snippet || issue.comment_content}
            </pre>
          </div>
        )}

        {/* =========================================================
            SOURCE-TO-SINK AST TAINT FLOW PIPELINE (2026 AI DEFENSE)
            ========================================================= */}
        {taintChain && taintChain.length > 0 && (
          <div
            className="webcare-firewall-section-group"
            style={{
              padding: '14px 16px',
              borderRadius: '10px',
              border: '1px solid var(--webcare-border, #e2e8f0)',
              background: 'var(--webcare-bg-surface, #f8fafc)',
              display: 'flex',
              flexDirection: 'column',
              gap: '12px'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <div
                  style={{
                    width: '26px',
                    height: '26px',
                    borderRadius: '6px',
                    background: 'rgba(239, 68, 68, 0.14)',
                    color: '#dc2626',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center'
                  }}
                >
                  <ShieldAlert size={15} />
                </div>
                <div>
                  <div style={{ fontSize: '12.5px', fontWeight: 800, color: 'var(--webcare-text-primary, #0f172a)' }}>
                    Source-to-Sink AST Taint Flow Trace
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                    2026 AI-Era Polymorphic Webshell Defense &bull; Token Flow Graph
                  </div>
                </div>
              </div>

              <span
                className="webcare-badge-pill"
                style={{
                  background: 'rgba(239, 68, 68, 0.14)',
                  color: '#dc2626',
                  border: '1px solid rgba(239, 68, 68, 0.35)',
                  fontSize: '11px',
                  fontWeight: 700,
                  padding: '3px 9px',
                  borderRadius: '12px'
                }}
              >
                Polymorphic Execution Sink Detected
              </span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {taintChain.map((step: any, sIdx: number) => {
                const stepType = String(step.type || 'step').toLowerCase();
                const isSource = stepType === 'source';
                const isSink = stepType === 'sink';
                const badgeBg = isSource ? '#fffbeb' : isSink ? '#fef2f2' : '#eef2ff';
                const badgeColor = isSource ? '#b45309' : isSink ? '#dc2626' : '#4338ca';
                const badgeBorder = isSource ? '#fde68a' : isSink ? '#fecaca' : '#c7d2fe';

                return (
                  <div
                    key={`taint-step-${sIdx}`}
                    style={{
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: '10px',
                      padding: '10px 12px',
                      borderRadius: '8px',
                      background: 'var(--webcare-bg-panel, #ffffff)',
                      border: '1px solid var(--webcare-border, #e2e8f0)',
                      position: 'relative'
                    }}
                  >
                    <div
                      style={{
                        minWidth: '22px',
                        height: '22px',
                        borderRadius: '50%',
                        background: isSink ? '#dc2626' : isSource ? '#d97706' : '#4f46e5',
                        color: '#ffffff',
                        fontSize: '11px',
                        fontWeight: 800,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        marginTop: '1px'
                      }}
                    >
                      {sIdx + 1}
                    </div>

                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '3px', flexWrap: 'wrap' }}>
                        <span
                          style={{
                            fontSize: '10px',
                            fontWeight: 800,
                            textTransform: 'uppercase',
                            padding: '1px 6px',
                            borderRadius: '4px',
                            background: badgeBg,
                            color: badgeColor,
                            border: `1px solid ${badgeBorder}`
                          }}
                        >
                          {isSource ? 'Taint Source' : isSink ? 'Execution Sink' : 'Propagation Step'}
                        </span>
                        {step.line && (
                          <span style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', fontFamily: 'monospace' }}>
                            Line #{step.line}
                          </span>
                        )}
                      </div>
                      <div style={{ fontSize: '12px', color: 'var(--webcare-text-primary, #0f172a)', wordBreak: 'break-word', fontFamily: isSink || isSource ? 'monospace' : 'inherit' }}>
                        {step.description || step.snippet || 'Taint propagated'}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>

            <div style={{ fontSize: '11px', color: 'var(--webcare-text-secondary, #475569)', fontStyle: 'italic', lineHeight: 1.4 }}>
              💡 <strong>How WebCare caught this:</strong> Traditional regex signatures scored 0 because this file uses benign variable names and standard library functions without obfuscation. WebCare's AST Taint Engine traced untrusted user data from the source directly into an execution sink.
            </div>
          </div>
        )}

        {/* =========================================================
            TECHNICAL EVIDENCE & AUDIT FOOTER
            ========================================================= */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '12px',
            paddingTop: '12px',
            borderTop: '1px solid var(--webcare-border, #e2e8f0)',
            fontSize: '11.5px',
            color: 'var(--webcare-text-muted, #64748b)'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px', flexWrap: 'wrap' }}>
            <span>Target: <strong style={{ color: 'var(--webcare-text-primary, #0f172a)' }}>{issue.file_path || issue.location || 'WordPress'}</strong></span>
            {issue.sha256 && (
              <span>SHA-256: <code>{issue.sha256.substring(0, 16)}...</code></span>
            )}
            {issue.evidence && typeof issue.evidence === 'string' && !issue.evidence.trim().startsWith('{') && (
              <span>Signature: <code>{issue.evidence}</code></span>
            )}
          </div>

          {issue.file_path && onCopyPath && (
            <button
              type="button"
              onClick={() => onCopyPath(issue.file_path)}
              style={{
                background: 'none',
                border: 'none',
                cursor: 'pointer',
                color: copiedPath === issue.file_path ? '#16a34a' : 'var(--webcare-text-muted, #64748b)',
                fontSize: '11px',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '4px'
              }}
            >
              {copiedPath === issue.file_path ? <Check size={12} color="#16a34a" /> : <Copy size={12} />}
              <span>{copiedPath === issue.file_path ? 'Path Copied' : 'Copy File Path'}</span>
            </button>
          )}
        </div>
      </div>
    </SafeErrorBoundary>
  );
};
