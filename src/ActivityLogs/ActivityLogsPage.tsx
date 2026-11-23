import React, { useState, useEffect, useMemo } from 'react';
import { generateStandardLogFilename } from '../exportUtils';
import { showAlert } from '../utils/dialog';
import {
  Activity,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  RefreshCw,
  Search,
  Download,
  CheckCircle2,
  Lock,
  ChevronDown,
  ChevronUp,
  User,
  Cpu,
  Clock,
  Filter,
  Eye,
  X,
  FileText,
  Copy,
  Check,
  Database,
  Shield,
  Layers,
  Terminal,
  Server,
  Zap,
  Globe,
  HelpCircle,
  Hash,
  Sliders,
  ChevronLeft,
  ChevronRight,
  Info,
  Key,
  Package,
  UserCheck
} from 'lucide-react';

interface ActivityRecord {
  seq: number;
  event_id: string;
  datetime: string;
  timestamp: number;
  category: string;
  action: string;
  severity: 'info' | 'notice' | 'warning' | 'error' | 'critical';
  friendly_title?: string;
  friendly_description?: string;
  friendly_badge?: string;
  friendly_badge_label?: string;
  is_system_internal?: boolean;
  actor: {
    type: string;
    id: number;
    user_login: string;
    display_name: string;
    role: string;
    ip: string;
    user_agent?: string;
  };
  executor: {
    type: string;
    identifier: string;
    pid: number;
  };
  details: {
    description?: string;
    module?: string;
    diff?: Record<string, { old: any; new: any }>;
    [key: string]: any;
  };
  prev_hash: string;
}

function formatRelativeTime(dateStr?: string): string {
  if (!dateStr) return 'N/A';
  try {
    const d = new Date(dateStr.endsWith('Z') ? dateStr : dateStr + 'Z');
    const now = new Date();
    const diffSec = Math.floor((now.getTime() - d.getTime()) / 1000);
    if (diffSec < 60) return 'Just now';
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
    if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
    if (diffSec < 604800) return `${Math.floor(diffSec / 86400)}d ago`;
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  } catch (e) {
    return dateStr;
  }
}

interface VerificationReport {
  status: 'verified' | 'tampering_detected' | 'incomplete_history' | 'verification_error';
  checked_records: number;
  broken_at_seq: number | null;
  details: string;
}

interface ActivityLogsPageProps {
  apiRequest: (options: { path: string; method?: string; data?: any }) => Promise<any>;
}

const WAF_RULE_TITLES: Record<string, string> = {
  waf_block_sqli: 'SQL Injection (SQLi) Defense',
  waf_block_xss: 'Cross-Site Scripting (XSS) Defense',
  waf_block_traversal: 'Directory Traversal & LFI Defense',
  waf_block_php_injection: 'Remote Code Execution & PHP Injection Defense',
  waf_block_fake_bots: 'Fake Search Engine Bots Defense',
  waf_block_ai_scrapers: 'AI Scrapers & LLM Crawler Blocker',
  waf_block_404_scanners: 'Aggressive 404 Scanner Protection',
  waf_block_empty_post_ua_referer: 'Empty User-Agent / Referer POST Protection',
  waf_block_empty_user_agent: 'Empty / Missing User-Agent Shield',
  waf_enable_progressive_warnings: 'Progressive Enforcement Warnings (Soft Block)',
  waf_contact_support_url: 'Support / Contact Page URL',
  waf_block_forbidden_usernames: 'Forbidden Default Admin Usernames Shield',
  waf_block_malicious_uploads: 'Malicious File Upload Inspection',
  waf_block_unsafe_http_methods: 'Unsafe HTTP Methods Filter',
  waf_block_null_byte_attacks: 'Null Byte Poisoning Defense',
  waf_block_sensitive_file_probes: 'Sensitive System File Probes Shield',
  waf_block_uploads_php_exec: 'Uploads PHP Execution Blocker',
  waf_block_external_cron: 'External WP-Cron Protection',
  waf_block_open_redirects: 'Open Redirect Defense',
  waf_block_ssrf_metadata: 'SSRF & Cloud Metadata Protection',
  waf_block_install_php: 'Direct install.php / setup-config.php Blocker',
  waf_block_rest_user_enum: 'REST API User Enumeration Shield',
  waf_block_author_scan: 'Author Query String User Enumeration Shield',
  waf_block_oversized_requests: 'Oversized Request Payload Guard',
  waf_block_ai_prompt_injection: 'AI Prompt Injection Defense',
  waf_disable_xmlrpc: 'Disable XML-RPC API',
  waf_enabled: 'Web Application Firewall (WAF) Master Switch',
  waf_mode: 'Web Application Firewall (WAF) Mode',
  waf_blocked_ips: 'Custom Blocked IP List',
};

// Helper: converts technical setting/rule keys into human-readable plain-English labels
function getFriendlySettingName(key: string): string {
  if (WAF_RULE_TITLES[key]) {
    return WAF_RULE_TITLES[key];
  }
  const clean = key.replace(/^waf_block_|^waf_|^threat_intel_|^webcareproscan_/, '');
  return clean.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

// Plain-English Action Translator for Non-Technical Users
function formatActivitySummary(rec: ActivityRecord): { title: string; subtitle: string; icon: React.ElementType; badgeColor: string } {
  const action = rec.action || '';
  const details = rec.details || {};

  switch (action) {
    case 'firewall_ruleset_modified': {
      const diff = details.diff || {};
      const diffKeys = Object.keys(diff);

      if (diffKeys.length === 1) {
        const key = diffKeys[0];
        const ruleName = WAF_RULE_TITLES[key] || key.replace(/^waf_block_|^waf_/, '').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
        const newVal = diff[key]?.new;

        if (key === 'waf_blocked_ips') {
          return {
            title: 'Firewall Blocked IP List Updated',
            subtitle: details.description || 'Custom blocked IP addresses list was updated in Firewall Settings.',
            icon: Shield,
            badgeColor: 'webcare-badge-info',
          };
        }

        if (key === 'waf_mode') {
          return {
            title: `Firewall Mode: ${String(newVal || '').toUpperCase()}`,
            subtitle: details.description || `Firewall operating mode changed to ${String(newVal || '').toUpperCase()}.`,
            icon: Shield,
            badgeColor: newVal === 'block' ? 'webcare-badge-clean' : (newVal === 'disabled' ? 'webcare-badge-danger' : 'webcare-badge-warning'),
          };
        }

        const isTurnedOn = newVal === true || newVal === 'enabled' || newVal === 1 || newVal === '1';
        const actorUser = rec.actor?.user_login || rec.actor?.display_name || 'admin';
        const actorIp = rec.actor?.ip || 'N/A';
        const actionText = isTurnedOn ? 'turned on' : 'turned off';

        return {
          title: `${ruleName} ${isTurnedOn ? 'Turned On' : 'Turned Off'}`,
          subtitle: details.description || `${ruleName} is ${actionText} by ${actorUser} with IP ${actorIp}.`,
          icon: Shield,
          badgeColor: isTurnedOn ? 'webcare-badge-clean' : 'webcare-badge-warning',
        };
      }

      const changed = details.changed_count || (diffKeys.length || 1);
      return {
        title: `Firewall Policy Updated (${changed} setting${changed === 1 ? '' : 's'})`,
        subtitle: details.description || 'Firewall protection rules or access controls were adjusted.',
        icon: Shield,
        badgeColor: 'webcare-badge-warning',
      };
    }
    case 'firewall_status_toggled': {
      const isEnabled = details.enabled;
      return {
        title: isEnabled ? 'Web Application Firewall (WAF) Activated' : 'Web Application Firewall (WAF) Paused',
        subtitle: isEnabled ? 'Active request filtering and attack defense are now protecting the site.' : 'Firewall packet filtering is currently paused.',
        icon: Shield,
        badgeColor: isEnabled ? 'webcare-badge-clean' : 'webcare-badge-danger',
      };
    }
    case 'settings_updated': {
      const count = details.changed_count || (details.diff ? Object.keys(details.diff).length : 1);
      return {
        title: `Scanner Settings Adjusted (${count} change${count === 1 ? '' : 's'})`,
        subtitle: details.description || 'Plugin configuration or automated scan schedule parameters were saved.',
        icon: Layers,
        badgeColor: 'webcare-badge-info',
      };
    }
    case 'manual_scan_started':
    case 'scan_started': {
      const target = details.scan_target || details.scan_type || 'Selected files';
      return {
        title: 'Security Scan Initiated',
        subtitle: `Manual malware and integrity scan started for "${target}".`,
        icon: Activity,
        badgeColor: 'webcare-badge-info',
      };
    }
    case 'scheduled_scan_started': {
      return {
        title: 'Automated Scheduled Scan Triggered',
        subtitle: 'Scheduled WP-Cron security verification started in background.',
        icon: Clock,
        badgeColor: 'webcare-badge-info',
      };
    }
    case 'scheduled_scan_completed':
    case 'scan_completed': {
      const infected = details.infected_count || 0;
      return {
        title: infected > 0 ? `Scan Completed (${infected} Threat${infected === 1 ? '' : 's'} Found)` : 'Security Scan Completed Clean',
        subtitle: infected > 0 ? 'Threats detected during inspection requiring review.' : 'All inspected files passed cryptographic integrity checks with zero viruses found.',
        icon: infected > 0 ? AlertTriangle : CheckCircle2,
        badgeColor: infected > 0 ? 'webcare-badge-danger' : 'webcare-badge-clean',
      };
    }
    case 'file_quarantined': {
      const file = details.file ? details.file.split(/[\\/]/).pop() : 'Malicious file';
      return {
        title: `File Quarantined: ${file}`,
        subtitle: `Isolated suspicious payload to encrypted quarantine vault. Original path: ${details.file || 'unknown'}`,
        icon: ShieldAlert,
        badgeColor: 'webcare-badge-danger',
      };
    }
    case 'file_restored': {
      const file = details.file ? details.file.split(/[\\/]/).pop() : 'File';
      return {
        title: `File Restored: ${file}`,
        subtitle: 'Restored original clean file from quarantine vault back to filesystem.',
        icon: CheckCircle2,
        badgeColor: 'webcare-badge-clean',
      };
    }
    case 'audit_init': {
      return {
        title: 'Cryptographic Audit Ledger Initialized',
        subtitle: 'Initial genesis checkpoint established with continuous SHA-256 hash chaining.',
        icon: Lock,
        badgeColor: 'webcare-badge-clean',
      };
    }
    case 'tamper_incident_detected': {
      return {
        title: 'CRITICAL: Forensic Tamper Incident Detected!',
        subtitle: details.reason || 'Cryptographic chain verification detected log discrepancy or modified sequence.',
        icon: AlertTriangle,
        badgeColor: 'webcare-badge-danger',
      };
    }
    case 'behavioral_learning_updated': {
      const changed = details.changed_count || (details.diff ? Object.keys(details.diff).length : 1);
      return {
        title: `Behavioral WAF Learning Mode Updated (${changed} setting${changed === 1 ? '' : 's'})`,
        subtitle: details.description || 'Adaptive learning thresholds, graduation confidence, or auto-tune options were saved.',
        icon: Sliders,
        badgeColor: 'webcare-badge-info',
      };
    }
    case 'honeytoken_settings_updated': {
      const changed = details.changed_count || (details.diff ? Object.keys(details.diff).length : 1);
      return {
        title: `Honey-Token Bot Traps Modified (${changed} setting${changed === 1 ? '' : 's'})`,
        subtitle: details.description || 'Decoy form honeypots, phantom endpoints, or auto-ban durations were saved.',
        icon: Zap,
        badgeColor: 'webcare-badge-warning',
      };
    }
    case 'rate_limiter_settings_updated': {
      const changed = details.changed_count || (details.diff ? Object.keys(details.diff).length : 1);
      return {
        title: `Adaptive Rate Limiter Updated (${changed} setting${changed === 1 ? '' : 's'})`,
        subtitle: details.description || 'API request rate limits, XML-RPC limits, or auto-escalation thresholds were updated.',
        icon: Clock,
        badgeColor: 'webcare-badge-warning',
      };
    }
    case 'ghost_route_settings_updated': {
      const changed = details.changed_count || (details.diff ? Object.keys(details.diff).length : 1);
      return {
        title: `Ghost Route Decoys Updated (${changed} setting${changed === 1 ? '' : 's'})`,
        subtitle: details.description || 'Phantom REST route traps or canary links were reconfigured.',
        icon: Shield,
        badgeColor: 'webcare-badge-info',
      };
    }
    case 'egress_firewall_settings_updated': {
      const changed = details.changed_count || (details.diff ? Object.keys(details.diff).length : 1);
      return {
        title: `Outbound Egress & SSRF Policy Updated (${changed} setting${changed === 1 ? '' : 's'})`,
        subtitle: details.description || 'Outbound destination allowlists and webhook egress rules were modified.',
        icon: Globe,
        badgeColor: 'webcare-badge-info',
      };
    }
    case 'prompt_injection_settings_updated': {
      const changed = details.changed_count || (details.diff ? Object.keys(details.diff).length : 1);
      return {
        title: `AI Prompt Injection Shield Updated (${changed} setting${changed === 1 ? '' : 's'})`,
        subtitle: details.description || 'LLM prompt override protection and decoy triggers were reconfigured.',
        icon: ShieldAlert,
        badgeColor: 'webcare-badge-warning',
      };
    }
    case 'gatekeeper_settings_updated': {
      const changed = details.changed_count || (details.diff ? Object.keys(details.diff).length : 1);
      return {
        title: `Supply-Chain Gatekeeper Policy Updated (${changed} setting${changed === 1 ? '' : 's'})`,
        subtitle: details.description || 'Pre-install plugin inspection rules and snapshot policies were saved.',
        icon: Layers,
        badgeColor: 'webcare-badge-info',
      };
    }
    case 'session_forensics_settings_updated': {
      const changed = details.changed_count || (details.diff ? Object.keys(details.diff).length : 1);
      return {
        title: `Zero-Trust Session Forensics Updated (${changed} setting${changed === 1 ? '' : 's'})`,
        subtitle: details.description || 'Impossible travel velocity checks or user-agent hijack sensors were reconfigured.',
        icon: User,
        badgeColor: 'webcare-badge-info',
      };
    }
    case 'virtual_patch_applied': {
      const title = details.title || details.patch_id || 'Virtual Patch';
      const cve = details.cve_id ? ` [${details.cve_id}]` : '';
      const cfBadge = details.cloudflare ? ' (Cloudflare Edge & PHP WAF Lite)' : ' (Local PHP WAF Lite)';
      return {
        title: `Virtual Shield Activated: ${title}${cve}`,
        subtitle: details.description || `Applied real-time virtual exploit patch${cfBadge}.`,
        icon: ShieldAlert,
        badgeColor: 'webcare-badge-clean',
      };
    }
    case 'virtual_patch_deactivated':
    case 'virtual_patch_removed': {
      const title = details.title || details.patch_id || 'Virtual Patch';
      return {
        title: `Virtual Shield Deactivated: ${title}`,
        subtitle: details.description || `Deactivated virtual hotpatch ${details.patch_id || ''}.`,
        icon: ShieldAlert,
        badgeColor: 'webcare-badge-warning',
      };
    }
    case 'virtual_patch_rules_modified': {
      const count = details.changed_count || (details.diff ? Object.keys(details.diff).length : 1);
      return {
        title: `Virtual Hotpatch Ruleset Updated (${count} rule${count === 1 ? '' : 's'})`,
        subtitle: details.description || 'Active virtual hotpatches and edge firewall expressions were updated.',
        icon: Shield,
        badgeColor: 'webcare-badge-info',
      };
    }
    case 'synthesized_virtual_patch_deployed': {
      return {
        title: `Synthesized Patch Deployed: ${details.title || 'Hotpatch'}`,
        subtitle: details.description || 'Autonomous AI-synthesized hotpatch generated and deployed to firewall filter.',
        icon: Zap,
        badgeColor: 'webcare-badge-clean',
      };
    }
    case 'whitelist_policy_modified':
    case 'whitelist_rule_added':
    case 'whitelist_rule_deleted': {
      return {
        title: 'False Positive Whitelist Modified',
        subtitle: details.description || 'Safe suppression rule or trusted IP list updated.',
        icon: CheckCircle2,
        badgeColor: 'webcare-badge-info',
      };
    }
    case 'auth_success':
    case 'user_login': {
      return {
        title: 'User Authenticated',
        subtitle: details.description || 'WordPress administrative session initiated.',
        icon: User,
        badgeColor: 'webcare-badge-clean',
      };
    }
    case 'auth_failed': {
      return {
        title: 'Authentication Attempt Failed',
        subtitle: details.description || 'Invalid credentials or brute force attempt blocked.',
        icon: AlertTriangle,
        badgeColor: 'webcare-badge-danger',
      };
    }
    case 'plugin_activated':
    case 'plugin_deactivated': {
      return {
        title: action === 'plugin_activated' ? 'WordPress Plugin Activated' : 'WordPress Plugin Deactivated',
        subtitle: details.description || 'Site extension lifecycle state changed.',
        icon: Layers,
        badgeColor: 'webcare-badge-info',
      };
    }
    case 'emergency_containment_activated': {
      return {
        title: 'EMERGENCY CONTAINMENT SHIELD ENGAGED',
        subtitle: details.description || 'Filesystem frozen to read-only; all non-admin sessions terminated.',
        icon: AlertTriangle,
        badgeColor: 'webcare-badge-danger',
      };
    }
    case 'emergency_containment_deactivated': {
      return {
        title: 'Emergency Containment Shield Disengaged',
        subtitle: details.description || 'Normal read-write filesystem operations and sessions restored.',
        icon: CheckCircle2,
        badgeColor: 'webcare-badge-clean',
      };
    }
    case 'policy_updated': {
      const option = String(details.option || '').toLowerCase();
      if (option.includes('micro_waf_status')) {
        return {
          title: 'Pre-Boot Micro-WAF Engine Synchronized',
          subtitle: 'Standalone Pre-Boot Micro-WAF script recompiled into wp-content/micro-waf.php to enforce active rules and IP blocklists.',
          icon: Zap,
          badgeColor: 'webcare-badge-clean',
          badgeLabel: 'Pre-Boot Firewall',
        };
      }
      if (option.includes('ip_reputation_log')) {
        return {
          title: 'IP Threat Reputation Cache Updated',
          subtitle: 'Autonomous risk scores and behavioral evaluation cache updated for client IP addresses.',
          icon: Globe,
          badgeColor: 'webcare-badge-info',
          badgeLabel: 'Threat Intelligence',
        };
      }
      if (option.includes('blocked_ips_meta')) {
        return {
          title: 'Firewall IP Blocklist Registry Synchronized',
          subtitle: 'Ban duration, strike counter, and tracking metadata updated for blocked IP addresses.',
          icon: ShieldAlert,
          badgeColor: 'webcare-badge-info',
          badgeLabel: 'Firewall Policy',
        };
      }
      if (option.includes('self_defense_last_audit')) {
        return {
          title: 'Self-Defense Cryptographic Integrity Audit',
          subtitle: 'Automated background audit verified plugin file hashes and digital manifests against tampering.',
          icon: ShieldCheck,
          badgeColor: 'webcare-badge-clean',
          badgeLabel: 'Self-Defense',
        };
      }
      if (option.includes('wizard_completed')) {
        return {
          title: 'Initial Security Onboarding Completed',
          subtitle: 'Initial setup wizard completed; recommended baseline firewall and hardening rules applied.',
          icon: CheckCircle2,
          badgeColor: 'webcare-badge-clean',
          badgeLabel: 'Setup Wizard',
        };
      }
      if (option.includes('site_archetype')) {
        const arch = details.diff?.webcareproscan_site_archetype?.new || 'Standard';
        const cleanArch = String(arch).replace(/\b\w/g, (c: string) => c.toUpperCase());
        return {
          title: `Site Archetype Profile Configured: ${cleanArch}`,
          subtitle: `Security scanner operational posture calibrated for site archetype "${cleanArch}".`,
          icon: Layers,
          badgeColor: 'webcare-badge-info',
          badgeLabel: 'Site Profile',
        };
      }
      if (option.includes('server_security_options')) {
        return {
          title: 'Web Server Armor Configuration Updated',
          subtitle: 'Server-level hardening directives updated for web server rules (.htaccess / Nginx).',
          icon: Shield,
          badgeColor: 'webcare-badge-clean',
          badgeLabel: 'Server Armor',
        };
      }
      if (option.includes('waf_whitelisted_ips')) {
        return {
          title: 'Firewall Trusted IP Allowlist Updated',
          subtitle: 'Trusted IP allowlist updated. Permitted IP addresses bypass standard WAF filtering.',
          icon: CheckCircle2,
          badgeColor: 'webcare-badge-clean',
          badgeLabel: 'Firewall Policy',
        };
      }
      if (option.includes('waf_settings')) {
        return {
          title: 'WAF Defense Settings Saved',
          subtitle: details.description || 'Web Application Firewall inspection modes and detection thresholds were saved.',
          icon: Shield,
          badgeColor: 'webcare-badge-info',
          badgeLabel: 'Firewall Policy',
        };
      }
      if (option.includes('notification_settings')) {
        return {
          title: 'Security Alert Channels Configured',
          subtitle: details.description || 'Security incident alert delivery channels and email notifications were updated.',
          icon: Sliders,
          badgeColor: 'webcare-badge-info',
          badgeLabel: 'Notifications',
        };
      }
      if (option.includes('circuit_breaker')) {
        return {
          title: 'CrashGuard Self-Preservation Engaged',
          subtitle: 'Firewall hooks were temporarily paused to keep your site online after an uncaught PHP error.',
          icon: ShieldAlert,
          badgeColor: 'webcare-badge-warning',
          badgeLabel: 'Self-Preservation',
        };
      }
      if (option.includes('gatekeeper_logs')) {
        return {
          title: 'Plugin Update Integrity Verified',
          subtitle: 'WebCare Gatekeeper confirmed updated plugin files have zero malicious payloads.',
          icon: Package,
          badgeColor: 'webcare-badge-clean',
          badgeLabel: 'Extension Security',
        };
      }
      if (option.includes('threat_intel')) {
        return {
          title: 'Threat Intelligence Feed Synchronized',
          subtitle: 'Automated background sync updated active botnet and attacker IPs.',
          icon: Globe,
          badgeColor: 'webcare-badge-info',
          badgeLabel: 'Threat Intelligence',
        };
      }
      if (option.includes('ghost_trap')) {
        return {
          title: 'Decoy Bot Trap Telemetry Logged',
          subtitle: 'Automated malicious vulnerability scanner intercepted by ghost honeypot trap.',
          icon: Zap,
          badgeColor: 'webcare-badge-warning',
          badgeLabel: 'Decoy Defense',
        };
      }
      if (option.includes('webauthn_index')) {
        return {
          title: 'Biometric Security Registry Synchronized',
          subtitle: 'Cryptographic public keys synchronized for passwordless biometric passkeys.',
          icon: Key,
          badgeColor: 'webcare-badge-clean',
          badgeLabel: 'Identity & Auth',
        };
      }
      const readableOption = option ? option.replace('webcareproscan_', '').replace(/_/g, ' ').replace(/\b\w/g, (c: string) => c.toUpperCase()) : 'Security Policy';
      const count = details.changed_count || (details.diff ? Object.keys(details.diff).length : 1);
      return {
        title: rec.friendly_title || `${readableOption} Adjusted (${count} setting${count === 1 ? '' : 's'})`,
        subtitle: rec.friendly_description || `Configuration parameters updated for ${readableOption}.`,
        icon: Sliders,
        badgeColor: 'webcare-badge-info',
        badgeLabel: 'Security Policy',
      };
    }
    case 'permission_hardening': {
      return {
        title: 'Filesystem Permission Hardening',
        subtitle: details.description || '1-Click filesystem permission repair applied: directories set to 0755 and sensitive files to 0644.',
        icon: ShieldCheck,
        badgeColor: 'webcare-badge-clean',
        badgeLabel: 'Filesystem',
      };
    }
    case 'script_baseline_calibrated': {
      return {
        title: 'Supply Chain Script Baseline Calibrated',
        subtitle: details.description || 'Calibrated approved external domains and script integrity for supply chain monitoring.',
        icon: Package,
        badgeColor: 'webcare-badge-clean',
        badgeLabel: 'Extension Security',
      };
    }
    case 'domain_reputation_anomaly': {
      return {
        title: 'Domain Reputation & Health Audit',
        subtitle: details.description || 'Domain reputation check evaluated domain health and security blacklists.',
        icon: Globe,
        badgeColor: 'webcare-badge-info',
        badgeLabel: 'System Health',
      };
    }
    case 'gatekeeper_update_audited': {
      const slug = details.plugin_slug || 'Plugin';
      const cleanSlug = slug.replace(/-/g, ' ').replace(/\b\w/g, (c: string) => c.toUpperCase());
      return {
        title: `Safe Plugin Update: ${cleanSlug}`,
        subtitle: `WebCare Gatekeeper verified update for "${cleanSlug}". Cryptographic code inspection confirmed zero malware.`,
        icon: Package,
        badgeColor: 'webcare-badge-clean',
        badgeLabel: 'Extension Security',
      };
    }
    case 'login_lockout': {
      const ip = details.ip || rec.actor?.ip || 'Attacker IP';
      return {
        title: `Brute Force Login Lockout: ${ip}`,
        subtitle: `Attacker IP was locked out after 5 consecutive failed login attempts.`,
        icon: ShieldAlert,
        badgeColor: 'webcare-badge-danger',
        badgeLabel: 'Account Defense',
      };
    }
    case 'customer_lockout_unblocked': {
      const ip = details.ip || 'Customer IP';
      return {
        title: `Customer Store Access Granted: ${ip}`,
        subtitle: `Customer IP was unblocked with a 24-hour checkout bypass token.`,
        icon: CheckCircle2,
        badgeColor: 'webcare-badge-clean',
        badgeLabel: 'Store Protection',
      };
    }
    case 'impossible_travel_detected': {
      const user = rec.actor?.user_login || rec.actor?.display_name || 'admin';
      return {
        title: `Impossible Travel Alert: ${user}`,
        subtitle: `User logged in from geographically disparate regions within an impossibly brief timeframe.`,
        icon: ShieldAlert,
        badgeColor: 'webcare-badge-danger',
        badgeLabel: 'Identity & Auth',
      };
    }
    case 'webauthn_passkey_registered': {
      const name = details.label || details.name || 'Biometric Device';
      const user = rec.actor?.user_login || rec.actor?.display_name || 'admin';
      return {
        title: 'Biometric Passkey Registered',
        subtitle: `New hardware biometric passkey ("${name}") registered for ${user}.`,
        icon: Key,
        badgeColor: 'webcare-badge-clean',
        badgeLabel: 'Identity & Auth',
      };
    }
    case 'webauthn_passkey_deleted': {
      const user = rec.actor?.user_login || rec.actor?.display_name || 'admin';
      return {
        title: 'Biometric Passkey Revoked',
        subtitle: `Biometric passkey security credential was revoked for ${user}.`,
        icon: Key,
        badgeColor: 'webcare-badge-warning',
        badgeLabel: 'Identity & Auth',
      };
    }
    case 'webauthn_passkey_login_success': {
      const user = rec.actor?.user_login || rec.actor?.display_name || 'admin';
      return {
        title: 'Biometric Passkey Sign-In Verified',
        subtitle: `Passkey login verified for administrator ${user}.`,
        icon: Key,
        badgeColor: 'webcare-badge-clean',
        badgeLabel: 'Identity & Auth',
      };
    }
    case 'all_sessions_revoked': {
      const user = rec.actor?.user_login || rec.actor?.display_name || 'user';
      return {
        title: 'All Active Sessions Terminated',
        subtitle: `Security action: all active WordPress sessions and cookies revoked for ${user}.`,
        icon: Lock,
        badgeColor: 'webcare-badge-warning',
        badgeLabel: 'Identity & Auth',
      };
    }
    case 'route_graduated': {
      const route = details.route || 'API Route';
      return {
        title: 'Adaptive Learning Route Graduated',
        subtitle: `Route "${route}" reached 100% confidence with zero anomalies. Added to verified safe profile.`,
        icon: CheckCircle2,
        badgeColor: 'webcare-badge-clean',
        badgeLabel: 'Adaptive Learning',
      };
    }
    case 'cloudflare_ip_blocked': {
      const ip = details.ip || 'IP address';
      return {
        title: `Cloudflare Edge IP Blocked: ${ip}`,
        subtitle: details.description || `IP ${ip} was blocked at Cloudflare Edge.`,
        icon: Globe,
        badgeColor: 'webcare-badge-danger',
      };
    }
    case 'cloudflare_ip_unblocked': {
      const ip = details.ip;
      const ruleId = details.rule_id || '';
      const displayTarget = ip ? `IP ${ip}` : `Rule ${ruleId}`;
      return {
        title: `Cloudflare Edge Block Removed: ${displayTarget}`,
        subtitle: details.description || `Cloudflare Edge block rule for ${displayTarget} was removed.`,
        icon: Globe,
        badgeColor: 'webcare-badge-clean',
      };
    }
    case 'cloudflare_ip_whitelisted': {
      const ip = details.ip || 'IP address';
      return {
        title: `Cloudflare Edge IP Allowlisted: ${ip}`,
        subtitle: details.description || `IP ${ip} was added to Cloudflare Edge Allowlist.`,
        icon: Globe,
        badgeColor: 'webcare-badge-clean',
      };
    }
    case 'cloudflare_whitelist_removed': {
      const ip = details.ip;
      const ruleId = details.rule_id || '';
      const displayTarget = ip ? `IP ${ip}` : `Rule ${ruleId}`;
      return {
        title: `Cloudflare Edge Allowlist Removed: ${displayTarget}`,
        subtitle: details.description || `Cloudflare Edge allowlist rule for ${displayTarget} was removed.`,
        icon: Globe,
        badgeColor: 'webcare-badge-warning',
      };
    }
    case 'cloudflare_rules_deployed': {
      const count = details.rules_count || 1;
      return {
        title: `Cloudflare Edge Rules Deployed (${count})`,
        subtitle: details.description || `Custom Cloudflare WAF rules synchronized to Edge.`,
        icon: Globe,
        badgeColor: 'webcare-badge-clean',
      };
    }
    case 'cloudflare_rule_modified': {
      const ruleKey = details.rule_key || 'Edge Rule';
      const isEnabled = details.enabled;
      return {
        title: `Cloudflare Edge Rule ${isEnabled ? 'Activated' : 'Disabled'}: ${ruleKey}`,
        subtitle: details.description || `Edge security rule "${ruleKey}" was ${isEnabled ? 'activated' : 'disabled'}.`,
        icon: Globe,
        badgeColor: isEnabled ? 'webcare-badge-clean' : 'webcare-badge-warning',
      };
    }
    case 'cloudflare_rate_limiting_toggled': {
      const isEnabled = details.enabled;
      return {
        title: `Cloudflare Edge Rate Limiting ${isEnabled ? 'Activated' : 'Paused'}`,
        subtitle: details.description || `Edge rate limiting protection was ${isEnabled ? 'activated' : 'paused'}.`,
        icon: Globe,
        badgeColor: isEnabled ? 'webcare-badge-clean' : 'webcare-badge-warning',
      };
    }
    case 'cloudflare_cache_purged': {
      return {
        title: 'Cloudflare Edge Cache Purged',
        subtitle: details.description || 'Cloudflare CDN cache was purged.',
        icon: Globe,
        badgeColor: 'webcare-badge-info',
      };
    }
    case 'firewall_ip_whitelisted': {
      const ip = details.ip || 'IP address';
      return {
        title: `Firewall Allowlist Added: ${ip}`,
        subtitle: details.description || `IP ${ip} was added to trusted WAF allowlist.`,
        icon: Shield,
        badgeColor: 'webcare-badge-clean',
      };
    }
    case 'firewall_ip_unblocked': {
      const ip = details.ip || 'IP address';
      return {
        title: `Firewall IP Unblocked: ${ip}`,
        subtitle: details.description || `IP ${ip} was unblocked from firewall blocklist.`,
        icon: Shield,
        badgeColor: 'webcare-badge-clean',
      };
    }
    case 'firewall_ip_blocked': {
      const ip = details.ip || 'IP address';
      return {
        title: `Firewall Manual Block Added: ${ip}`,
        subtitle: details.description || `IP ${ip} was manually added to WAF blocklist.`,
        icon: ShieldAlert,
        badgeColor: 'webcare-badge-danger',
      };
    }
    case 'firewall_logs_cleared': {
      return {
        title: 'Firewall Incident Logs Cleared',
        subtitle: details.description || 'All historical WAF incident logs were purged by administrator.',
        icon: Shield,
        badgeColor: 'webcare-badge-warning',
      };
    }
    case 'server_security_saved': {
      const srv = (details.server_type || 'Server').toUpperCase();
      return {
        title: `${srv} Web Server Armor Updated`,
        subtitle: details.description || `Web server level rules for ${srv} were updated.`,
        icon: Shield,
        badgeColor: 'webcare-badge-clean',
      };
    }
    case 'server_security_htaccess_deployed': {
      return {
        title: 'Server Armor Rules Deployed to .htaccess',
        subtitle: details.description || 'Direct server-level security rules deployed to root .htaccess.',
        icon: ShieldAlert,
        badgeColor: 'webcare-badge-clean',
      };
    }
    case 'cloudflare_rate_limit_modified': {
      return {
        title: 'Cloudflare Edge Rate Limiting Updated',
        subtitle: details.description || 'Global Cloudflare Edge rate limiting rules and thresholds were synchronized.',
        icon: Globe,
        badgeColor: 'webcare-badge-info',
      };
    }
    case 'cloudflare_rules_modified': {
      return {
        title: 'Cloudflare Edge Firewall Rules Updated',
        subtitle: details.description || 'Active IP blocking or WAF rules synchronized to Cloudflare Global Edge.',
        icon: Globe,
        badgeColor: 'webcare-badge-info',
      };
    }
    case 'logs_pruned': {
      return {
        title: 'Expired Partitions Pruned',
        subtitle: details.description || 'Partitions older than retention threshold archived & cleared safely.',
        icon: Database,
        badgeColor: 'webcare-badge-info',
      };
    }
    default: {
      const readable = action.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
      return {
        title: readable,
        subtitle: details.description || (typeof details === 'string' ? details : JSON.stringify(details)),
        icon: Activity,
        badgeColor: 'webcare-badge-info',
      };
    }
  }
}

export function ActivityLogsPage({ apiRequest }: ActivityLogsPageProps) {
  const [records, setRecords] = useState<ActivityRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [verificationReport, setVerificationReport] = useState<VerificationReport | null>(null);
  const [tamperAlert, setTamperAlert] = useState<any>(null);
  const [selectedRecord, setSelectedRecord] = useState<ActivityRecord | null>(null);
  const [expandedSeq, setExpandedSeq] = useState<number | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Filters
  const [filterCategory, setFilterCategory] = useState<string>('all');
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [filterActorType, setFilterActorType] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [retentionDays, setRetentionDays] = useState(7);

  // View Mode: Simple (friendly for non-tech admins/clients) vs Technical (deep forensics & diffs)
  const [viewMode, setViewMode] = useState<'simple' | 'technical'>(() => {
    try {
      return (localStorage.getItem('webcare_activity_logs_view_mode') as 'simple' | 'technical') || 'simple';
    } catch (e) {
      return 'simple';
    }
  });

  const handleViewModeChange = (mode: 'simple' | 'technical') => {
    setViewMode(mode);
    try {
      localStorage.setItem('webcare_activity_logs_view_mode', mode);
    } catch (e) {
      // ignore
    }
  };

  // Export Modal State
  const [isExportModalOpen, setIsExportModalOpen] = useState(false);
  const [exportScope, setExportScope] = useState<'all' | 'date' | 'filtered'>('all');
  const [exportDate, setExportDate] = useState(() => new Date().toISOString().slice(0, 10));
  const [exportFormat, setExportFormat] = useState<'csv' | 'json'>('json');
  const [includeSystemInfo, setIncludeSystemInfo] = useState<boolean>(() => {
    try {
      const saved = localStorage.getItem('webcare_export_include_system_info');
      return saved !== null ? saved === 'true' : true;
    } catch (e) {
      return true;
    }
  });
  const [isExporting, setIsExporting] = useState(false);

  // Pagination
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [totalRecords, setTotalRecords] = useState<number>(0);
  const [perPage, setPerPage] = useState<number>(100);

  const loadLogs = async (pageToLoad = currentPage, pageSize = perPage) => {
    setLoading(true);
    try {
      let path = `/webcare-pro-security/v1/activity-logs?page=${pageToLoad}&limit=${pageSize}`;
      if (filterCategory !== 'all') path += `&category=${encodeURIComponent(filterCategory)}`;
      if (filterSeverity !== 'all') path += `&severity=${encodeURIComponent(filterSeverity)}`;
      if (filterActorType !== 'all') path += `&actor_type=${encodeURIComponent(filterActorType)}`;
      if (searchQuery.trim()) path += `&search=${encodeURIComponent(searchQuery.trim())}`;

      const res = await apiRequest({ path });
      if (res && res.records) {
        setRecords(res.records);
        if (res.total !== undefined) setTotalRecords(res.total);
        if (res.total_pages !== undefined) setTotalPages(res.total_pages || 1);
        if (res.current_page !== undefined) setCurrentPage(res.current_page || 1);
        if (res.tamper_alert) setTamperAlert(res.tamper_alert);
        if (res.settings && res.settings.retention_days) setRetentionDays(res.settings.retention_days);
      }
    } catch (e) {
      console.error('Failed to load activity logs', e);
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async () => {
    setVerifying(true);
    try {
      const res = await apiRequest({ path: '/webcare-pro-security/v1/activity-logs/verify' });
      if (res && res.report) {
        setVerificationReport(res.report);
      }
    } catch (e) {
      console.error('Verification failed', e);
    } finally {
      setVerifying(false);
    }
  };

  const executeExport = async () => {
    setIsExporting(true);
    try {
      const filename = generateStandardLogFilename('activity-logs', exportFormat, exportScope === 'date' ? exportDate : undefined);

      // Fetch environment telemetry snapshot if requested
      let envSnapshot: any = null;
      if (includeSystemInfo) {
        try {
          const snapRes = await apiRequest({
            path: '/webcare-pro-security/v1/telemetry/snapshot',
            method: 'GET'
          });
          if (snapRes && snapRes.snapshot) {
            envSnapshot = snapRes.snapshot;
          }
        } catch (snapErr) {
          console.warn('WebCare: Could not fetch telemetry snapshot for activity logs export', snapErr);
        }
      }

      if (exportScope === 'filtered') {
        // Export currently loaded filtered records in-browser
        if (exportFormat === 'json') {
          const exportPayload: any = {
            generator: 'WebCare Pro Security & Firewall - Activity & Audit Logs',
            exported_at_utc: new Date().toISOString(),
            scope: 'filtered',
            total_records: records.length,
            records: records,
          };
          if (includeSystemInfo && envSnapshot) {
            exportPayload.environment_snapshot = envSnapshot;
          }
          const jsonStr = JSON.stringify(exportPayload, null, 2);
          const blob = new Blob([jsonStr], { type: 'application/json;charset=utf-8' });
          triggerFileDownload(blob, filename);
        } else {
          downloadRecordsAsCsv(records, filename, envSnapshot);
        }
        setIsExportModalOpen(false);
        return;
      }

      // Scope is 'all' or 'date' -> trigger direct backend streaming export
      const params = new URLSearchParams();
      params.append('format', exportFormat);
      if (includeSystemInfo) {
        params.append('include_system_info', '1');
      }
      if (exportScope === 'date' && exportDate) {
        params.append('date', exportDate);
      }
      if (filterCategory !== 'all') params.append('category', filterCategory);
      if (filterSeverity !== 'all') params.append('severity', filterSeverity);
      if (filterActorType !== 'all') params.append('actor_type', filterActorType);
      if (searchQuery.trim()) params.append('search', searchQuery.trim());

      const restRoot = (window as any).webcareScannerSettings?.root || '/wp-json/webcare-pro-security/v1';
      const cleanRoot = restRoot.replace(/\/+$/, '');
      const exportUrl = `${cleanRoot}/activity-logs/export?${params.toString()}`;

      // Create an authenticated download fetch
      const nonce = (window as any).webcareScannerSettings?.nonce || '';
      const response = await fetch(exportUrl, {
        headers: {
          'X-WP-Nonce': nonce
        }
      });

      if (!response.ok) {
        throw new Error(`Export request failed with HTTP ${response.status}`);
      }

      const blob = await response.blob();
      triggerFileDownload(blob, filename);
      setIsExportModalOpen(false);
    } catch (err: any) {
      console.error('Failed to export activity logs:', err);
      await showAlert(err?.message || 'Failed to export activity logs.', 'Export Error');
    } finally {
      setIsExporting(false);
    }
  };

  const downloadRecordsAsCsv = (dataset: ActivityRecord[], filename: string, telemetry?: any) => {
    const escapeCell = (val: any): string => {
      if (val === null || val === undefined) return '""';
      let str = typeof val === 'object' ? JSON.stringify(val) : String(val);
      const trimmed = str.trim();
      if (trimmed.length > 0 && ['=', '+', '-', '@', '\t', '\r'].includes(trimmed[0])) {
        str = `'` + str;
      }
      return `"${str.replace(/"/g, '""')}"`;
    };

    const preambleLines: string[] = [];
    if (telemetry) {
      const cfText = telemetry?.edge_network?.powered_by_cloudflare
        ? `YES (${telemetry?.edge_network?.cloudflare_status || 'Cloudflare Edge'})`
        : 'NO (Direct Origin)';
      const actPlugins = telemetry?.plugins?.active_plugins || [];
      const actPluginsStr = actPlugins.slice(0, 15).map((p: any) => p.name).join(', ') +
        (actPlugins.length > 15 ? ` ... (+${actPlugins.length - 15} more)` : '');

      preambleLines.push('# =============================================================================');
      preambleLines.push('# WebCare Pro Security & Firewall - AUDIT & ACTIVITY LOG EXPORT');
      preambleLines.push(`# Site Domain: ${telemetry?.site?.domain || 'Unknown'} | Real Server IP: ${telemetry?.server?.real_ip || 'Unknown'}`);
      preambleLines.push(`# Cloudflare Edge: ${cfText}`);
      preambleLines.push(`# Server Software: ${telemetry?.server?.software || 'Unknown'} | PHP: ${telemetry?.server?.php_version || 'Unknown'} | WP Core: ${telemetry?.wordpress?.core_version || 'Unknown'}`);
      preambleLines.push(`# Active Theme: ${telemetry?.theme?.active_theme?.name || 'Unknown'} (v${telemetry?.theme?.active_theme?.version || 'Unknown'})`);
      preambleLines.push(`# Active Plugins (${actPlugins.length}): ${actPluginsStr}`);
      preambleLines.push(`# Exported At (UTC): ${telemetry?.exported_at_utc || new Date().toISOString()}`);
      preambleLines.push('# =============================================================================');
    }

    const headers = [
      'Sequence',
      'Event ID',
      'UTC Datetime',
      'Category',
      'Severity',
      'Action',
      'Plain English Title',
      'Actor Type',
      'Actor Login',
      'Actor Role',
      'Actor IP',
      'Executor Type',
      'Details Summary',
    ];

    const csvRows = [...preambleLines, headers.map(escapeCell).join(',')];

    for (const rec of dataset) {
      const sum = formatActivitySummary(rec);
      const row = [
        rec.seq,
        rec.event_id,
        rec.datetime,
        rec.category,
        rec.severity,
        rec.action,
        sum.title,
        rec.actor?.type || 'system',
        rec.actor?.user_login || '',
        rec.actor?.role || '',
        rec.actor?.ip || '',
        rec.executor?.type || '',
        typeof rec.details === 'object' ? JSON.stringify(rec.details) : String(rec.details || ''),
      ];
      csvRows.push(row.map(escapeCell).join(','));
    }

    const csvContent = '\uFEFF' + csvRows.join('\r\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    triggerFileDownload(blob, filename);
  };

  const triggerFileDownload = (blob: Blob, filename: string) => {
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    setTimeout(() => {
      document.body.removeChild(anchor);
      URL.revokeObjectURL(url);
    }, 250);
  };

  const handleDismissTamper = async () => {
    if (!tamperAlert?.incident_id) return;
    try {
      await apiRequest({
        path: '/webcare-pro-security/v1/activity-logs/acknowledge-tamper',
        method: 'POST',
        data: { incident_id: tamperAlert.incident_id },
      });
      setTamperAlert(null);
    } catch (e) {
      console.error('Failed to acknowledge tamper alert', e);
    }
  };

  const copyToClipboard = (text: string, key: string) => {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text);
    } else {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  useEffect(() => {
    setCurrentPage(1);
    loadLogs(1, perPage);
  }, [filterCategory, filterSeverity, filterActorType]);

  const handlePageChange = (newPage: number) => {
    if (newPage < 1 || newPage > totalPages || newPage === currentPage) return;
    setCurrentPage(newPage);
    loadLogs(newPage, perPage);
  };

  const handlePerPageChange = (newLimit: number) => {
    setPerPage(newLimit);
    setCurrentPage(1);
    loadLogs(1, newLimit);
  };

  // Compute Top KPI Statistics
  const stats = useMemo(() => {
    const total = records.length;
    let human = 0;
    let automated = 0;
    records.forEach((r) => {
      if (r.actor?.type === 'user') human++;
      else automated++;
    });
    return { total, human, automated };
  }, [records]);

  const getSeverityBadgeClass = (sev: string) => {
    switch (sev) {
      case 'critical':
      case 'error':
        return 'webcare-badge-danger';
      case 'warning':
        return 'webcare-badge-warning';
      case 'notice':
        return 'webcare-badge-info';
      default:
        return 'webcare-badge-clean';
    }
  };

  return (
    <div className="webcare-page-container" style={{ padding: '24px 0' }}>
      {/* Quick-Switch Cross-Link Bar */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '8px 16px',
          marginBottom: '16px',
          borderRadius: '8px',
          background: 'var(--webcare-bg-surface, #f8fafc)',
          border: '1px solid var(--webcare-border, #e2e8f0)',
          fontSize: '12.5px',
          color: 'var(--webcare-text-secondary, #475569)'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <button
            type="button"
            onClick={() => { window.location.href = 'admin.php?page=webcare-pro-firewall&tab=waf-rules'; }}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '4px 10px',
              borderRadius: '6px',
              fontSize: '12px',
              fontWeight: 600,
              background: 'var(--webcare-bg-panel, #ffffff)',
              border: '1px solid var(--webcare-border, #cbd5e1)',
              color: 'var(--webcare-text-primary, #0f172a)',
              cursor: 'pointer'
            }}
          >
            <span>← Firewall Rules &amp; Presets</span>
          </button>
          <span style={{ color: 'var(--webcare-border, #cbd5e1)' }}>|</span>
          <button
            type="button"
            onClick={() => { window.location.href = 'admin.php?page=webcare-pro-logs&tab=firewall'; }}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '5px',
              padding: '4px 10px',
              borderRadius: '6px',
              fontSize: '12px',
              fontWeight: 600,
              background: 'transparent',
              border: 'none',
              color: '#4f46e5',
              cursor: 'pointer'
            }}
          >
            <span>WAF Incident Logs &amp; Bans</span>
          </button>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <button
            type="button"
            onClick={() => { window.location.href = 'admin.php?page=webcare-pro-settings'; }}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '5px',
              padding: '4px 10px',
              borderRadius: '6px',
              fontSize: '12px',
              fontWeight: 600,
              background: 'transparent',
              border: '1px solid var(--webcare-border, #cbd5e1)',
              color: 'var(--webcare-text-primary, #0f172a)',
              cursor: 'pointer'
            }}
          >
            <span>Settings &amp; Doctor →</span>
          </button>
        </div>
      </div>

      {/* Header Banner */}
      <div className="webcare-header-card webcare-mb-4" style={{ padding: '20px 24px', borderRadius: '14px' }}>
        <div className="webcare-flex webcare-items-center webcare-justify-between" style={{ flexWrap: 'wrap', gap: '16px' }}>
          <div className="webcare-flex webcare-items-center webcare-gap-3">
            <div className="webcare-icon-box webcare-icon-box-primary" style={{ width: '44px', height: '44px' }}>
              <Activity className="webcare-w-6 webcare-h-6" />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <h1 className="webcare-text-xl webcare-font-bold webcare-text-primary" style={{ margin: 0, fontSize: '20px' }}>
                  Plugin Activity &amp; Audit Logs
                </h1>
                <span className="webcare-badge-pill webcare-badge-clean" style={{ fontSize: '11px', fontWeight: 700 }}>
                  AES-256-GCM AEAD
                </span>
                <span className="webcare-badge-pill" style={{ background: 'rgba(99, 102, 241, 0.12)', color: '#6366f1', border: '1px solid rgba(99, 102, 241, 0.3)', fontSize: '11px', fontWeight: 700 }}>
                  7-Day Immutability
                </span>
              </div>
              <p className="webcare-text-sm webcare-text-muted" style={{ margin: '4px 0 0 0' }}>
                Cryptographically chained, zero-SQL forensic telemetry. Every administrator change and security event is permanently signed and verifiable.
              </p>
            </div>
          </div>

          <div className="webcare-flex webcare-items-center webcare-gap-2" style={{ flexWrap: 'wrap' }}>
            <button
              type="button"
              onClick={handleVerify}
              disabled={verifying}
              className="webcare-btn webcare-btn-secondary webcare-flex webcare-items-center webcare-gap-1.5"
              style={{ fontWeight: 600, fontSize: '13px', padding: '8px 14px' }}
              title="Recalculate continuous SHA-256 hashes from genesis to active partition"
            >
              <ShieldCheck className={`webcare-w-4 webcare-h-4 ${verifying ? 'webcare-animate-spin' : 'webcare-text-emerald-500'}`} />
              <span>{verifying ? 'Verifying Hashes...' : 'Verify Cryptographic Integrity'}</span>
            </button>

            <button
              type="button"
              onClick={() => setIsExportModalOpen(true)}
              className="webcare-btn webcare-btn-secondary webcare-flex webcare-items-center webcare-gap-1.5"
              style={{ fontSize: '13px', padding: '8px 14px', fontWeight: 600 }}
              title="Configure and download forensic activity logs"
            >
              <Download className="webcare-w-4 webcare-h-4" />
              <span>Export Logs</span>
            </button>

            <button
              type="button"
              onClick={loadLogs}
              disabled={loading}
              className="webcare-btn webcare-btn-secondary"
              style={{ padding: '8px 12px' }}
              title="Refresh Stream"
            >
              <RefreshCw className={`webcare-w-4 webcare-h-4 ${loading ? 'webcare-animate-spin' : ''}`} />
            </button>
          </div>
        </div>
      </div>

      {/* Emergency Tamper Alert Banner */}
      {tamperAlert && (
        <div className="webcare-alert-banner-danger webcare-mb-4" style={{ padding: '16px 20px', borderRadius: '12px', border: '1px solid #f87171' }}>
          <div className="webcare-flex webcare-items-start webcare-justify-between" style={{ gap: '16px' }}>
            <div className="webcare-flex webcare-items-start webcare-gap-3">
              <AlertTriangle className="webcare-w-6 webcare-h-6 webcare-text-danger webcare-flex-shrink-0" style={{ marginTop: '2px' }} />
              <div>
                <h3 className="webcare-font-bold webcare-text-danger" style={{ margin: 0, fontSize: '16px' }}>
                  CRITICAL: Cryptographic Log Tampering Detected!
                </h3>
                <p className="webcare-text-sm webcare-mt-1" style={{ margin: '4px 0 0 0' }}>
                  Incident ID: <code>{tamperAlert.incident_id}</code> &bull; Sequence #{tamperAlert.details?.seq} in file <strong>{tamperAlert.details?.file}</strong>.<br />
                  Forensic Reason: <strong>{tamperAlert.details?.reason}</strong>
                </p>
              </div>
            </div>
            <button
              type="button"
              onClick={handleDismissTamper}
              className="webcare-btn webcare-btn-sm webcare-btn-danger"
              style={{ fontWeight: 700 }}
            >
              Acknowledge &amp; Dismiss
            </button>
          </div>
        </div>
      )}

      {/* Verification Result Callout */}
      {verificationReport && (
        <div
          className={`webcare-card webcare-mb-4 webcare-p-4 webcare-border-l-4 ${
            verificationReport.status === 'verified'
              ? 'webcare-border-emerald-500 webcare-bg-emerald-50'
              : 'webcare-border-rose-500 webcare-bg-rose-50'
          }`}
          style={{ borderRadius: '10px' }}
        >
          <div className="webcare-flex webcare-items-center webcare-justify-between" style={{ flexWrap: 'wrap', gap: '12px' }}>
            <div className="webcare-flex webcare-items-center webcare-gap-3">
              {verificationReport.status === 'verified' ? (
                <CheckCircle2 className="webcare-w-6 webcare-h-6 webcare-text-emerald-600" />
              ) : (
                <ShieldAlert className="webcare-w-6 webcare-h-6 webcare-text-rose-600" />
              )}
              <div>
                <span className="webcare-font-bold webcare-text-sm" style={{ display: 'block' }}>
                  Cryptographic Ledger Status: {verificationReport.status.toUpperCase()}
                </span>
                <span className="webcare-text-xs webcare-text-muted">
                  {verificationReport.details} ({verificationReport.checked_records} total cryptographic envelopes verified unbroken).
                </span>
              </div>
            </div>
            <button
              type="button"
              onClick={() => setVerificationReport(null)}
              className="webcare-btn-micro webcare-btn-secondary"
              title="Dismiss report"
            >
              <X className="webcare-w-3.5 webcare-h-3.5" />
            </button>
          </div>
        </div>
      )}

      {/* Top 4 KPI Summary Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '14px', marginBottom: '18px' }}>
        {/* KPI 1: Total Events */}
        <div className="webcare-card" style={{ padding: '16px 20px', borderRadius: '12px', border: '1px solid var(--webcare-border, #e2e8f0)', display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{ width: '42px', height: '42px', borderRadius: '10px', background: 'rgba(2, 132, 199, 0.12)', color: '#0284c7', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
            <Database size={22} />
          </div>
          <div>
            <div style={{ fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', color: 'var(--webcare-text-muted, #64748b)', letterSpacing: '0.5px' }}>
              Logged Events
            </div>
            <div style={{ fontSize: '20px', fontWeight: 800, color: 'var(--webcare-text-primary, #0f172a)', marginTop: '2px' }}>
              {stats.total} Records
            </div>
          </div>
        </div>

        {/* KPI 2: Human Admin Actions */}
        <div className="webcare-card" style={{ padding: '16px 20px', borderRadius: '12px', border: '1px solid var(--webcare-border, #e2e8f0)', display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{ width: '42px', height: '42px', borderRadius: '10px', background: 'rgba(99, 102, 241, 0.12)', color: '#4f46e5', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
            <User size={22} />
          </div>
          <div>
            <div style={{ fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', color: 'var(--webcare-text-muted, #64748b)', letterSpacing: '0.5px' }}>
              Admin Modifications
            </div>
            <div style={{ fontSize: '20px', fontWeight: 800, color: 'var(--webcare-text-primary, #0f172a)', marginTop: '2px' }}>
              {stats.human} Actions
            </div>
          </div>
        </div>

        {/* KPI 3: System Automated Events */}
        <div className="webcare-card" style={{ padding: '16px 20px', borderRadius: '12px', border: '1px solid var(--webcare-border, #e2e8f0)', display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{ width: '42px', height: '42px', borderRadius: '10px', background: 'rgba(16, 185, 129, 0.12)', color: '#10b981', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
            <Cpu size={22} />
          </div>
          <div>
            <div style={{ fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', color: 'var(--webcare-text-muted, #64748b)', letterSpacing: '0.5px' }}>
              Automated Guards
            </div>
            <div style={{ fontSize: '20px', fontWeight: 800, color: 'var(--webcare-text-primary, #0f172a)', marginTop: '2px' }}>
              {stats.automated} Events
            </div>
          </div>
        </div>

        {/* KPI 4: Chain Health & Immutability */}
        <div className="webcare-card" style={{ padding: '16px 20px', borderRadius: '12px', border: '1px solid var(--webcare-border, #e2e8f0)', display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{ width: '42px', height: '42px', borderRadius: '10px', background: 'rgba(14, 165, 233, 0.12)', color: '#0ea5e9', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
            <Lock size={22} />
          </div>
          <div>
            <div style={{ fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', color: 'var(--webcare-text-muted, #64748b)', letterSpacing: '0.5px' }}>
              Forensic Lock
            </div>
            <div style={{ fontSize: '20px', fontWeight: 800, color: '#10b981', marginTop: '2px' }}>
              7-Day Immutability
            </div>
          </div>
        </div>
      </div>

      {/* Filter Toolbar Card */}
      <div className="webcare-card webcare-waf-toolbar-card webcare-mb-4" style={{ padding: '14px 18px', borderRadius: '12px', display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '12px' }}>
        {/* Search */}
        <div style={{ flex: 1, minWidth: 260 }}>
          <div className="webcare-search-box" style={{ padding: '7px 12px' }}>
            <Search size={15} style={{ color: 'var(--webcare-text-muted, #94a3b8)', flexShrink: 0 }} />
            <input
              type="text"
              className="webcare-search-input"
              placeholder="Search action name, IP address, username, setting key..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  setCurrentPage(1);
                  loadLogs(1, perPage);
                }
              }}
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => {
                  setSearchQuery('');
                  setCurrentPage(1);
                  setTimeout(() => loadLogs(1, perPage), 0);
                }}
                className="webcare-btn-micro webcare-btn-secondary"
                style={{ padding: '2px 5px', fontSize: '11px', lineHeight: 1 }}
                title="Clear search"
              >
                &times;
              </button>
            )}
          </div>
        </div>

        {/* Category Filter */}
        <select
          className="webcare-select"
          value={filterCategory}
          onChange={(e) => setFilterCategory(e.target.value)}
          style={{ fontSize: '13px', fontWeight: 600, minWidth: '160px' }}
        >
          <option value="all">All Event Categories</option>
          <option value="firewall">Firewall &amp; WAF Rules</option>
          <option value="settings">Plugin Settings</option>
          <option value="scan">Malware Scans</option>
          <option value="quarantine">Quarantine &amp; Vault</option>
          <option value="crashguard">CrashGuard Forensics</option>
          <option value="retention">Retention &amp; Checkpoints</option>
          <option value="system">System &amp; Defense</option>
        </select>

        {/* Severity Filter */}
        <select
          className="webcare-select"
          value={filterSeverity}
          onChange={(e) => setFilterSeverity(e.target.value)}
          style={{ fontSize: '13px', fontWeight: 600, minWidth: '130px' }}
        >
          <option value="all">All Severities</option>
          <option value="info">Info</option>
          <option value="notice">Notice</option>
          <option value="warning">Warning</option>
          <option value="error">Error</option>
          <option value="critical">Critical</option>
        </select>

        {/* Actor Type Filter */}
        <select
          className="webcare-select"
          value={filterActorType}
          onChange={(e) => setFilterActorType(e.target.value)}
          style={{ fontSize: '13px', fontWeight: 600, minWidth: '140px' }}
        >
          <option value="all">All Initiators</option>
          <option value="user">Human Administrators</option>
          <option value="system">Automated System / Cron</option>
        </select>

        <button
          type="button"
          onClick={() => {
            setCurrentPage(1);
            loadLogs(1, perPage);
          }}
          className="webcare-btn webcare-btn-primary webcare-flex webcare-items-center webcare-gap-1.5"
          style={{ fontSize: '13px', fontWeight: 600, padding: '8px 16px' }}
        >
          <Filter className="webcare-w-4 webcare-h-4" />
          <span>Apply Filter</span>
        </button>

        {/* View Mode Toggle: Simple vs Technical */}
        <div style={{ marginLeft: 'auto', display: 'inline-flex', padding: '3px', background: 'var(--webcare-surface-elevated, #f1f5f9)', borderRadius: '8px', border: '1px solid var(--webcare-border, #e2e8f0)', gap: '3px' }}>
          <button
            type="button"
            onClick={() => handleViewModeChange('simple')}
            className={`webcare-btn-micro ${viewMode === 'simple' ? 'webcare-btn-primary' : 'webcare-btn-ghost'}`}
            style={{ display: 'inline-flex', alignItems: 'center', gap: '5px', padding: '5px 12px', borderRadius: '6px', fontSize: '12px', fontWeight: 700 }}
            title="Clean, friendly view for non-technical administrators & clients"
          >
            <UserCheck size={13} />
            <span>Simple View</span>
          </button>
          <button
            type="button"
            onClick={() => handleViewModeChange('technical')}
            className={`webcare-btn-micro ${viewMode === 'technical' ? 'webcare-btn-primary' : 'webcare-btn-ghost'}`}
            style={{ display: 'inline-flex', alignItems: 'center', gap: '5px', padding: '5px 12px', borderRadius: '6px', fontSize: '12px', fontWeight: 700 }}
            title="Deep technical forensic view with raw option diffs & cryptographic signatures"
          >
            <Terminal size={13} />
            <span>Technical View</span>
          </button>
        </div>
      </div>

      {/* Records Table Card */}
      <div className="webcare-card webcare-overflow-hidden" style={{ borderRadius: '12px', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
        <div className="webcare-table-responsive">
          <table className="webcare-table webcare-w-full">
            <thead>
              {viewMode === 'simple' ? (
                <tr>
                  <th style={{ width: 44, textAlign: 'center' }}></th>
                  <th style={{ width: 165 }}>Category</th>
                  <th>Security Activity &amp; Summary</th>
                  <th style={{ width: 185 }}>Performed By</th>
                  <th style={{ width: 140 }}>When</th>
                  <th style={{ width: 85, textAlign: 'right' }}>Details</th>
                </tr>
              ) : (
                <tr>
                  <th style={{ width: 44, textAlign: 'center' }}></th>
                  <th style={{ width: 75 }}>Seq</th>
                  <th style={{ width: 145 }}>Time (UTC)</th>
                  <th style={{ width: 90 }}>Severity</th>
                  <th style={{ width: 130 }}>Category</th>
                  <th>Security Event &amp; Technical Action</th>
                  <th style={{ width: 175 }}>Initiator</th>
                  <th style={{ width: 110, textAlign: 'right' }}>Actions</th>
                </tr>
              )}
            </thead>
            <tbody>
              {records.length === 0 ? (
                <tr>
                  <td colSpan={viewMode === 'simple' ? 6 : 8} className="webcare-text-center webcare-p-8 webcare-text-muted" style={{ padding: '48px 20px' }}>
                    <Activity size={36} style={{ margin: '0 auto 12px auto', opacity: 0.3 }} />
                    <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>
                      {loading ? 'Decrypting AES-256-GCM activity stream...' : 'No admin changes recorded yet in the last 7 days.'}
                    </div>
                    <p style={{ margin: '4px 0 0 0', fontSize: '12px' }}>
                      {loading ? 'Verifying cryptographic envelope authentication tags...' : 'No administrator activity or configuration changes match your active filters.'}
                    </p>
                  </td>
                </tr>
              ) : (
                records.map((rec) => {
                  const summary = formatActivitySummary(rec);
                  const IconComp = summary.icon;
                  const isExpanded = expandedSeq === rec.seq;
                  const hasDiff = rec.details?.diff && Object.keys(rec.details.diff).length > 0;

                  return (
                    <React.Fragment key={rec.event_id}>
                      {viewMode === 'simple' ? (
                        /* Simple Friendly Row */
                        <tr
                          className={`webcare-hover-lift ${isExpanded ? 'webcare-row-expanded' : ''}`}
                          style={{ cursor: 'pointer' }}
                          onClick={() => setExpandedSeq(isExpanded ? null : rec.seq)}
                        >
                          {/* Expand Toggle */}
                          <td style={{ textAlign: 'center', padding: '12px 6px' }}>
                            <button
                              type="button"
                              className="webcare-btn-micro webcare-btn-secondary"
                              onClick={(e) => {
                                e.stopPropagation();
                                setExpandedSeq(isExpanded ? null : rec.seq);
                              }}
                              title={isExpanded ? 'Collapse activity card' : 'Expand activity card'}
                            >
                              {isExpanded ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
                            </button>
                          </td>

                          {/* Category Badge */}
                          <td>
                            <span className={`webcare-badge-pill ${summary.badgeColor}`} style={{ fontSize: '11px', fontWeight: 700 }}>
                              {summary.badgeLabel || rec.friendly_badge_label || rec.category}
                            </span>
                          </td>

                          {/* Plain English Summary */}
                          <td style={{ padding: '12px 14px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                              <div style={{ width: '30px', height: '30px', borderRadius: '8px', background: 'var(--webcare-surface-elevated, #f1f5f9)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                                <IconComp size={15} color="#0284c7" />
                              </div>
                              <div style={{ minWidth: 0, flex: 1 }}>
                                <div style={{ fontSize: '13.5px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                                  {summary.title}
                                </div>
                                <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px', lineHeight: 1.4 }}>
                                  {summary.subtitle}
                                </div>
                              </div>
                            </div>
                          </td>

                          {/* Actor */}
                          <td>
                            {rec.actor?.type === 'user' ? (
                              <span className="webcare-firewall-role-chip webcare-flex webcare-items-center webcare-gap-1.5" style={{ fontSize: '11.5px' }}>
                                <User className="webcare-w-3.5 webcare-h-3.5" />
                                <strong style={{ fontWeight: 700 }}>{rec.actor.user_login || rec.actor.display_name}</strong>
                                <span style={{ opacity: 0.7 }}>({rec.actor.role || 'admin'})</span>
                              </span>
                            ) : (
                              <span className="webcare-badge-pill webcare-badge-clean webcare-flex webcare-items-center webcare-gap-1.5" style={{ fontSize: '11px', fontWeight: 600 }}>
                                <Cpu className="webcare-w-3.5 webcare-h-3.5" />
                                <span>Automated Guard</span>
                              </span>
                            )}
                          </td>

                          {/* When */}
                          <td className="webcare-text-xs webcare-text-muted" style={{ whiteSpace: 'nowrap' }}>
                            <div style={{ fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>
                              {formatRelativeTime(rec.datetime)}
                            </div>
                            <div style={{ fontSize: '10.5px', opacity: 0.75 }}>
                              {rec.datetime ? new Date(rec.datetime.endsWith('Z') ? rec.datetime : rec.datetime + 'Z').toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ''}
                            </div>
                          </td>

                          {/* Quick View Button */}
                          <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                            <button
                              type="button"
                              className="webcare-btn-micro webcare-btn-secondary"
                              onClick={(e) => {
                                e.stopPropagation();
                                setExpandedSeq(isExpanded ? null : rec.seq);
                              }}
                              title="Inspect Details"
                            >
                              <Eye className="webcare-w-3.5 webcare-h-3.5" />
                            </button>
                          </td>
                        </tr>
                      ) : (
                        /* Technical View Row */
                        <tr
                          className={`webcare-hover-lift ${isExpanded ? 'webcare-row-expanded' : ''}`}
                          style={{ cursor: 'pointer' }}
                          onClick={() => setExpandedSeq(isExpanded ? null : rec.seq)}
                        >
                          <td style={{ textAlign: 'center', padding: '12px 6px' }}>
                            <button
                              type="button"
                              className="webcare-btn-micro webcare-btn-secondary"
                              onClick={(e) => {
                                e.stopPropagation();
                                setExpandedSeq(isExpanded ? null : rec.seq);
                              }}
                              title={isExpanded ? 'Collapse forensic drawer' : 'Expand forensic drawer'}
                            >
                              {isExpanded ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
                            </button>
                          </td>

                          <td className="webcare-font-mono webcare-text-xs" style={{ fontWeight: 700, color: '#0284c7' }}>
                            #{rec.seq}
                          </td>

                          <td className="webcare-text-xs webcare-text-muted" style={{ whiteSpace: 'nowrap' }}>
                            {rec.datetime?.replace('T', ' ').replace('Z', '')}
                          </td>

                          <td>
                            <span className={`webcare-badge-pill ${getSeverityBadgeClass(rec.severity)}`} style={{ fontSize: '10px', fontWeight: 700 }}>
                              {rec.severity.toUpperCase()}
                            </span>
                          </td>

                          <td>
                            <span className="webcare-badge-pill webcare-badge-info" style={{ fontSize: '11px', textTransform: 'capitalize' }}>
                              {rec.category}
                            </span>
                          </td>

                          <td>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                              <div style={{ width: '24px', height: '24px', borderRadius: '6px', background: 'var(--webcare-surface-elevated, #f1f5f9)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                                <IconComp size={13} color="#0284c7" />
                              </div>
                              <div style={{ minWidth: 0, flex: 1 }}>
                                <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                                  {summary.title}
                                </div>
                                <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: '420px' }}>
                                  <code style={{ fontSize: '11px', color: '#0284c7' }}>{rec.action}</code>
                                  {summary.subtitle && ` \u2014 ${summary.subtitle}`}
                                </div>
                              </div>
                            </div>
                          </td>

                          <td>
                            {rec.actor?.type === 'user' ? (
                              <span className="webcare-firewall-role-chip webcare-flex webcare-items-center webcare-gap-1" style={{ fontSize: '11.5px', maxWidth: '160px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                <User className="webcare-w-3 webcare-h-3" />
                                <strong style={{ fontWeight: 700 }}>{rec.actor.user_login || rec.actor.display_name}</strong>
                                <span style={{ opacity: 0.7 }}>({rec.actor.role || 'admin'})</span>
                              </span>
                            ) : (
                              <span className="webcare-badge-pill webcare-badge-info webcare-flex webcare-items-center webcare-gap-1" style={{ fontSize: '11px' }}>
                                <Cpu className="webcare-w-3 webcare-h-3" />
                                <span>{rec.actor?.display_name || 'System Guard'}</span>
                              </span>
                            )}
                          </td>

                          <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                            <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                              {hasDiff && (
                                <button
                                  type="button"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setSelectedRecord(rec);
                                  }}
                                  className="webcare-btn-micro webcare-btn-secondary"
                                  title="Inspect Setting Values Diff"
                                >
                                  <Eye className="webcare-w-3.5 webcare-h-3.5" />
                                </button>
                              )}

                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  copyToClipboard(JSON.stringify(rec, null, 2), `row_json_${rec.seq}`);
                                }}
                                className="webcare-btn-micro webcare-btn-secondary"
                                title="Copy Decrypted JSON"
                              >
                                {copiedKey === `row_json_${rec.seq}` ? (
                                  <Check className="webcare-w-3.5 webcare-h-3.5 webcare-text-emerald-500" />
                                ) : (
                                  <Copy className="webcare-w-3.5 webcare-h-3.5" />
                                )}
                              </button>
                            </div>
                          </td>
                        </tr>
                      )}

                      {/* Expandable Drawer Row */}
                      {isExpanded && (
                        viewMode === 'simple' ? (
                          /* Simple Friendly Expanded Card */
                          <tr className="webcare-waf-expanded-row">
                            <td colSpan={6} style={{ padding: '16px 20px' }}>
                              <div className="webcare-card" style={{ padding: '18px 22px', borderRadius: '10px', border: '1px solid var(--webcare-border, #e2e8f0)', background: 'var(--webcare-bg-card, #ffffff)' }}>
                                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', flexWrap: 'wrap', gap: '10px' }}>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                                    <span className={`webcare-badge-pill ${summary.badgeColor}`} style={{ fontSize: '11px', fontWeight: 700 }}>
                                      {summary.badgeLabel || rec.friendly_badge_label || rec.category.toUpperCase()}
                                    </span>
                                    <span style={{ fontSize: '15px', fontWeight: 800, color: 'var(--webcare-text-primary, #0f172a)' }}>
                                      {summary.title}
                                    </span>
                                  </div>
                                  <button
                                    type="button"
                                    className="webcare-btn-micro webcare-btn-ghost"
                                    onClick={() => handleViewModeChange('technical')}
                                    style={{ fontSize: '11.5px', textDecoration: 'underline', color: 'var(--webcare-text-muted)' }}
                                  >
                                    Inspect Technical Code &amp; JSON Diff &rarr;
                                  </button>
                                </div>

                                <div style={{ padding: '14px 18px', background: 'var(--webcare-surface-elevated, #f8fafc)', borderRadius: '8px', border: '1px solid var(--webcare-border, #e2e8f0)', marginBottom: '16px' }}>
                                  <div style={{ fontSize: '13.5px', color: 'var(--webcare-text-primary, #0f172a)', lineHeight: 1.6 }}>
                                    {summary.subtitle}
                                  </div>
                                </div>

                                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '12px' }}>
                                  <div style={{ padding: '10px 14px', borderRadius: '8px', border: '1px solid var(--webcare-border)', background: 'var(--webcare-bg-surface, #f8fafc)' }}>
                                    <div style={{ fontSize: '10.5px', fontWeight: 700, textTransform: 'uppercase', color: 'var(--webcare-text-muted)' }}>Initiator</div>
                                    <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-primary)', marginTop: '2px' }}>
                                      {rec.actor?.user_login || rec.actor?.display_name || 'System Automated Guard'}
                                    </div>
                                    <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted)' }}>
                                      Role: {rec.actor?.role || (rec.actor?.type === 'system' ? 'Background Cron / Guard' : 'Administrator')}
                                    </div>
                                  </div>

                                  <div style={{ padding: '10px 14px', borderRadius: '8px', border: '1px solid var(--webcare-border)', background: 'var(--webcare-bg-surface, #f8fafc)' }}>
                                    <div style={{ fontSize: '10.5px', fontWeight: 700, textTransform: 'uppercase', color: 'var(--webcare-text-muted)' }}>Network IP &amp; Origin</div>
                                    <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-primary)', marginTop: '2px', fontFamily: 'monospace' }}>
                                      {rec.actor?.ip || 'Internal System'}
                                    </div>
                                    <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted)' }}>
                                      Direct telemetry origin
                                    </div>
                                  </div>

                                  <div style={{ padding: '10px 14px', borderRadius: '8px', border: '1px solid var(--webcare-border)', background: 'var(--webcare-bg-surface, #f8fafc)' }}>
                                    <div style={{ fontSize: '10.5px', fontWeight: 700, textTransform: 'uppercase', color: 'var(--webcare-text-muted)' }}>Audit Ledger Integrity</div>
                                    <div style={{ fontSize: '13px', fontWeight: 700, color: '#10b981', marginTop: '2px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                                      <CheckCircle2 size={14} /> Cryptographically Sealed
                                    </div>
                                    <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted)' }}>
                                      Sequence #{rec.seq} &bull; SHA-256 chained
                                    </div>
                                  </div>
                                </div>
                              </div>
                            </td>
                          </tr>
                        ) : (
                          /* Technical Forensic Drawer Row */
                          <tr className="webcare-waf-expanded-row">
                            <td colSpan={8} style={{ padding: '16px 20px' }}>
                            <div className="webcare-waf-forensic-accordion" style={{ padding: '16px 20px', borderRadius: '10px' }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '14px', marginBottom: '14px', borderBottom: '1px solid var(--webcare-border)', paddingBottom: '12px' }}>
                                <div>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                    <h4 style={{ margin: 0, fontSize: '14px', fontWeight: 800, color: 'var(--webcare-text-primary, #0f172a)' }}>
                                      Forensic Event Dossier &bull; Sequence #{rec.seq}
                                    </h4>
                                    <span className="webcare-badge-pill webcare-badge-clean" style={{ fontSize: '10px', fontWeight: 700 }}>
                                      AUTHENTICATED GCM PAYLOAD
                                    </span>
                                  </div>
                                  <p style={{ margin: '3px 0 0 0', fontSize: '12px', color: 'var(--webcare-text-secondary, #64748b)' }}>
                                    Event ID: <code style={{ color: '#0284c7' }}>{rec.event_id}</code> &bull; Previous SHA-256 Hash: <code style={{ fontSize: '11px' }}>{rec.prev_hash ? rec.prev_hash.substring(0, 16) + '...' : 'GENESIS'}</code>
                                  </p>
                                </div>

                                {/* 1-Click Copy Toolbar */}
                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                                  <button
                                    type="button"
                                    onClick={() => copyToClipboard(JSON.stringify(rec, null, 2), `full_json_${rec.seq}`)}
                                    className="webcare-btn webcare-btn-secondary webcare-flex webcare-items-center webcare-gap-1"
                                    style={{ fontSize: '11.5px', padding: '5px 10px', fontWeight: 600 }}
                                    title="Copy complete decrypted cryptographic record as JSON"
                                  >
                                    {copiedKey === `full_json_${rec.seq}` ? <Check size={13} className="webcare-text-emerald-500" /> : <Copy size={13} />}
                                    <span>{copiedKey === `full_json_${rec.seq}` ? 'Copied JSON!' : 'Copy Full JSON'}</span>
                                  </button>

                                  <button
                                    type="button"
                                    onClick={() => copyToClipboard(rec.event_id, `id_${rec.seq}`)}
                                    className="webcare-btn webcare-btn-secondary webcare-flex webcare-items-center webcare-gap-1"
                                    style={{ fontSize: '11.5px', padding: '5px 10px', fontWeight: 600 }}
                                    title="Copy Event ID"
                                  >
                                    {copiedKey === `id_${rec.seq}` ? <Check size={13} className="webcare-text-emerald-500" /> : <Hash size={13} />}
                                    <span>{copiedKey === `id_${rec.seq}` ? 'Copied ID!' : 'Copy Event ID'}</span>
                                  </button>

                                  <button
                                    type="button"
                                    onClick={() => copyToClipboard(`[${rec.datetime}] [Seq #${rec.seq}] [${rec.category.toUpperCase()}] ${summary.title} - ${summary.subtitle} (Actor: ${rec.actor?.display_name || 'System'}, IP: ${rec.actor?.ip || 'N/A'})`, `text_${rec.seq}`)}
                                    className="webcare-btn webcare-btn-secondary webcare-flex webcare-items-center webcare-gap-1"
                                    style={{ fontSize: '11.5px', padding: '5px 10px', fontWeight: 600 }}
                                    title="Copy Human Readable Plain-English Summary"
                                  >
                                    {copiedKey === `text_${rec.seq}` ? <Check size={13} className="webcare-text-emerald-500" /> : <FileText size={13} />}
                                    <span>{copiedKey === `text_${rec.seq}` ? 'Copied Summary!' : 'Copy Plain Summary'}</span>
                                  </button>
                                </div>
                              </div>

                              {/* Forensic Details Grid */}
                              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '14px', marginBottom: '14px' }}>
                                {/* Actor Details */}
                                <div style={{ background: 'var(--webcare-bg-card, #ffffff)', padding: '12px 14px', borderRadius: '8px', border: '1px solid var(--webcare-border)' }}>
                                  <div style={{ fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', color: 'var(--webcare-text-muted)', marginBottom: '6px' }}>
                                    Actor &amp; Network Identity
                                  </div>
                                  <div style={{ fontSize: '12.5px', lineHeight: 1.6 }}>
                                    <div><strong>Type:</strong> <span style={{ textTransform: 'capitalize' }}>{rec.actor?.type}</span></div>
                                    <div><strong>User:</strong> {rec.actor?.user_login || rec.actor?.display_name || 'System Automated'}</div>
                                    <div><strong>Role:</strong> {rec.actor?.role || 'System'}</div>
                                    <div><strong>IP Address:</strong> <code>{rec.actor?.ip || '127.0.0.1'}</code></div>
                                    {rec.actor?.user_agent && (
                                      <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted)', wordBreak: 'break-all', marginTop: '4px' }}>
                                        <strong>User Agent:</strong> {rec.actor.user_agent}
                                      </div>
                                    )}
                                  </div>
                                </div>

                                {/* Executor Details */}
                                <div style={{ background: 'var(--webcare-bg-card, #ffffff)', padding: '12px 14px', borderRadius: '8px', border: '1px solid var(--webcare-border)' }}>
                                  <div style={{ fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', color: 'var(--webcare-text-muted)', marginBottom: '6px' }}>
                                    Runtime &amp; Execution Environment
                                  </div>
                                  <div style={{ fontSize: '12.5px', lineHeight: 1.6 }}>
                                    <div><strong>Executor Type:</strong> <code>{rec.executor?.type || 'web_request'}</code></div>
                                    <div><strong>Endpoint:</strong> <code style={{ wordBreak: 'break-all' }}>{rec.executor?.identifier || 'N/A'}</code></div>
                                    <div><strong>Process PID:</strong> <code>{rec.executor?.pid || 'N/A'}</code></div>
                                    <div><strong>Timestamp UTC:</strong> {rec.datetime}</div>
                                  </div>
                                </div>
                              </div>

                              {/* Diff or Parameters Section */}
                              {hasDiff ? (
                                <div style={{ marginTop: '10px' }}>
                                  {/* Center Highlighted Plain-English Summary Banner */}
                                  {rec.details?.description && (
                                    <div
                                      style={{
                                        margin: '0 0 14px 0',
                                        padding: '12px 18px',
                                        background: 'rgba(2, 132, 199, 0.08)',
                                        border: '1px solid rgba(2, 132, 199, 0.25)',
                                        borderRadius: '10px',
                                        display: 'flex',
                                        alignItems: 'center',
                                        justifyContent: 'center',
                                        textAlign: 'center',
                                        gap: '10px',
                                      }}
                                    >
                                      <Info size={16} color="#0284c7" style={{ flexShrink: 0 }} />
                                      <span
                                        style={{
                                          fontSize: '13.5px',
                                          fontWeight: 700,
                                          color: 'var(--webcare-text-primary, #0f172a)',
                                          lineHeight: 1.5,
                                        }}
                                      >
                                        {rec.details.description}
                                      </span>
                                    </div>
                                  )}

                                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                                    <div style={{ fontSize: '12.5px', fontWeight: 700, color: 'var(--webcare-text-primary)' }}>
                                      Modified Parameters (Before vs After):
                                    </div>
                                  </div>
                                  <div className="webcare-table-responsive" style={{ maxHeight: '240px', overflowY: 'auto', border: '1px solid var(--webcare-border)', borderRadius: '8px' }}>
                                    <table className="webcare-table webcare-w-full" style={{ fontSize: '12px' }}>
                                      <thead>
                                        <tr>
                                          <th style={{ width: '36%' }}>Setting / Security Rule</th>
                                          <th style={{ width: '32%' }}>Previous Value</th>
                                          <th style={{ width: '32%' }}>New Saved Value</th>
                                        </tr>
                                      </thead>
                                      <tbody>
                                        {Object.entries(rec.details.diff || {}).map(([key, diff]) => {
                                          const friendlyName = getFriendlySettingName(key);
                                          const isRuleKey = friendlyName !== key;
                                          return (
                                            <tr key={key}>
                                              <td style={{ padding: '8px 12px' }}>
                                                <div style={{ fontWeight: 700, color: 'var(--webcare-text-primary)', fontSize: '12.5px', marginBottom: isRuleKey ? '2px' : '0' }}>
                                                  {friendlyName}
                                                </div>
                                                {isRuleKey && (
                                                  <code style={{ fontSize: '10.5px', color: 'var(--webcare-text-muted)' }}>
                                                    {key}
                                                  </code>
                                                )}
                                              </td>
                                              <td style={{ color: '#dc2626', background: 'rgba(239, 68, 68, 0.08)', fontFamily: 'monospace', padding: '8px 12px', verticalAlign: 'middle' }}>
                                                {typeof diff.old === 'object' && diff.old !== null ? (
                                                  <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all', fontSize: '11px', maxHeight: '120px', overflowY: 'auto' }}>
                                                    {JSON.stringify(diff.old, null, 2)}
                                                  </pre>
                                                ) : (
                                                  String(diff.old ?? 'None')
                                                )}
                                              </td>
                                              <td style={{ color: '#059669', background: 'rgba(16, 185, 129, 0.08)', fontFamily: 'monospace', padding: '8px 12px', verticalAlign: 'middle' }}>
                                                {typeof diff.new === 'object' && diff.new !== null ? (
                                                  <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all', fontSize: '11px', maxHeight: '120px', overflowY: 'auto' }}>
                                                    {JSON.stringify(diff.new, null, 2)}
                                                  </pre>
                                                ) : (
                                                  String(diff.new ?? 'None')
                                                )}
                                              </td>
                                            </tr>
                                          );
                                        })}
                                      </tbody>
                                    </table>
                                  </div>
                                </div>
                              ) : (
                                <div style={{ background: 'var(--webcare-bg-card, #ffffff)', padding: '10px 14px', borderRadius: '8px', border: '1px solid var(--webcare-border)' }}>
                                  <div style={{ fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', color: 'var(--webcare-text-muted)', marginBottom: '4px' }}>
                                    Event Payload Details
                                  </div>
                                  <pre style={{ margin: 0, fontSize: '11.5px', fontFamily: 'monospace', whiteSpace: 'pre-wrap', wordBreak: 'break-all', color: 'var(--webcare-text-primary)' }}>
                                    {JSON.stringify(rec.details, null, 2)}
                                  </pre>
                                </div>
                              )}
                            </div>
                          </td>
                        </tr>
                      )
                    )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Toolbar Footer */}
        {totalRecords > 0 && (
          <div
            className="webcare-waf-toolbar-card"
            style={{
              padding: '12px 18px',
              borderTop: '1px solid var(--webcare-border, #e2e8f0)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '12px',
              background: 'var(--webcare-bg-surface-elevated, #f8fafc)',
              borderRadius: '0 0 12px 12px',
            }}
          >
            {/* Range Counter & Per Page */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
              <span className="webcare-text-xs webcare-text-muted" style={{ fontWeight: 600 }}>
                Showing{' '}
                <strong style={{ color: 'var(--webcare-text-primary, #0f172a)' }}>
                  {(currentPage - 1) * perPage + 1}
                </strong>{' '}
                to{' '}
                <strong style={{ color: 'var(--webcare-text-primary, #0f172a)' }}>
                  {Math.min(currentPage * perPage, totalRecords)}
                </strong>{' '}
                of{' '}
                <strong style={{ color: 'var(--webcare-text-primary, #0f172a)' }}>
                  {totalRecords}
                </strong>{' '}
                forensic events
              </span>

              {/* Per Page Selector */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span className="webcare-text-xs webcare-text-muted">Per page:</span>
                <select
                  className="webcare-select"
                  value={perPage}
                  onChange={(e) => handlePerPageChange(Number(e.target.value))}
                  style={{
                    fontSize: '12px',
                    padding: '3px 8px',
                    fontWeight: 600,
                    height: '28px',
                    minWidth: '70px',
                  }}
                >
                  <option value={100}>100</option>
                  <option value={200}>200</option>
                  <option value={500}>500</option>
                </select>
              </div>
            </div>

            {/* Pagination Controls */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <button
                type="button"
                onClick={() => handlePageChange(currentPage - 1)}
                disabled={currentPage <= 1 || loading}
                className="webcare-btn webcare-btn-secondary webcare-flex webcare-items-center webcare-gap-1"
                style={{
                  fontSize: '12px',
                  padding: '5px 12px',
                  fontWeight: 600,
                  opacity: currentPage <= 1 || loading ? 0.5 : 1,
                  cursor: currentPage <= 1 || loading ? 'not-allowed' : 'pointer',
                }}
              >
                <ChevronLeft size={14} />
                <span>Previous</span>
              </button>

              <span
                className="webcare-badge-pill webcare-badge-info"
                style={{
                  fontSize: '12px',
                  padding: '5px 12px',
                  fontWeight: 700,
                  minWidth: '90px',
                  textAlign: 'center',
                }}
              >
                Page {currentPage} of {totalPages}
              </span>

              <button
                type="button"
                onClick={() => handlePageChange(currentPage + 1)}
                disabled={currentPage >= totalPages || loading}
                className="webcare-btn webcare-btn-secondary webcare-flex webcare-items-center webcare-gap-1"
                style={{
                  fontSize: '12px',
                  padding: '5px 12px',
                  fontWeight: 600,
                  opacity: currentPage >= totalPages || loading ? 0.5 : 1,
                  cursor: currentPage >= totalPages || loading ? 'not-allowed' : 'pointer',
                }}
              >
                <span>Next</span>
                <ChevronRight size={14} />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Settings Diff Modal */}
      {selectedRecord && (
        <div
          className="webcare-modal-backdrop"
          style={{
            zIndex: 999999,
            position: 'fixed',
            inset: 0,
            background: 'rgba(15, 23, 42, 0.75)',
            backdropFilter: 'blur(8px)',
            WebkitBackdropFilter: 'blur(8px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '20px',
          }}
          onClick={(e) => {
            if (e.target === e.currentTarget) {
              setSelectedRecord(null);
            }
          }}
        >
          <div
            className="webcare-modal-window"
            style={{
              width: '100%',
              maxWidth: '680px',
              maxHeight: '90vh',
              height: 'auto',
              display: 'flex',
              flexDirection: 'column',
              borderRadius: '16px',
              background: 'var(--webcare-bg-card, #0f172a)',
              color: 'var(--webcare-text-primary, #f8fafc)',
              border: '1px solid var(--webcare-border, rgba(255, 255, 255, 0.12))',
              boxShadow: '0 25px 60px -15px rgba(0, 0, 0, 0.5), 0 0 25px rgba(2, 132, 199, 0.15)',
              overflow: 'hidden',
            }}
          >
            {/* Modal Header */}
            <div
              className="webcare-modal-header"
              style={{
                padding: '18px 24px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: '12px',
                background: 'var(--webcare-bg-surface-elevated, #1e293b)',
                borderBottom: '1px solid var(--webcare-border, rgba(255, 255, 255, 0.08))',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div
                  style={{
                    width: '40px',
                    height: '40px',
                    borderRadius: '10px',
                    background: 'rgba(2, 132, 199, 0.12)',
                    color: '#0284c7',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0,
                  }}
                >
                  <Eye size={20} />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: 'var(--webcare-text-primary, #f8fafc)' }}>
                    Settings Modification Diff &bull; Seq #{selectedRecord.seq}
                  </h3>
                  <p style={{ margin: '3px 0 0 0', fontSize: '12px', color: 'var(--webcare-text-secondary, #94a3b8)' }}>
                    Triggered by <strong>{selectedRecord.actor?.display_name || selectedRecord.actor?.user_login || 'System'}</strong> on {selectedRecord.datetime?.replace('T', ' ').replace('Z', ' UTC')}
                  </p>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <button
                  type="button"
                  onClick={() => copyToClipboard(JSON.stringify(selectedRecord.details?.diff || {}, null, 2), 'modal_diff_copy')}
                  className="webcare-btn webcare-btn-secondary webcare-flex webcare-items-center webcare-gap-1.5"
                  style={{ fontSize: '12px', padding: '6px 12px', fontWeight: 600 }}
                  title="Copy before/after diff as JSON"
                >
                  {copiedKey === 'modal_diff_copy' ? <Check size={13} className="webcare-text-emerald-500" /> : <Copy size={13} />}
                  <span>{copiedKey === 'modal_diff_copy' ? 'Copied Diff!' : 'Copy Diff JSON'}</span>
                </button>
                <button
                  type="button"
                  onClick={() => setSelectedRecord(null)}
                  className="webcare-modal-close-btn"
                  title="Close dialog"
                >
                  <X size={18} />
                </button>
              </div>
            </div>

            {/* Modal Body */}
            <div style={{ padding: '20px 24px', overflowY: 'auto', flex: 1, background: 'var(--webcare-bg-card, #0f172a)' }}>
              {selectedRecord.details?.description && (
                <div
                  style={{
                    margin: '0 0 16px 0',
                    padding: '12px 18px',
                    background: 'rgba(2, 132, 199, 0.12)',
                    border: '1px solid rgba(2, 132, 199, 0.3)',
                    borderRadius: '10px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    textAlign: 'center',
                    gap: '10px',
                  }}
                >
                  <Info size={16} color="#38bdf8" style={{ flexShrink: 0 }} />
                  <span
                    style={{
                      fontSize: '13.5px',
                      fontWeight: 700,
                      color: 'var(--webcare-text-primary, #f8fafc)',
                      lineHeight: 1.5,
                    }}
                  >
                    {selectedRecord.details.description}
                  </span>
                </div>
              )}

              <div style={{ marginBottom: '14px', fontSize: '12.5px', color: 'var(--webcare-text-secondary, #94a3b8)', lineHeight: 1.5 }}>
                Below are the exact configuration parameters that were altered in this transaction, comparing the previous state with the newly persisted state.
              </div>

              <div className="webcare-table-responsive" style={{ border: '1px solid var(--webcare-border, rgba(255, 255, 255, 0.1))', borderRadius: '10px', overflow: 'hidden' }}>
                <table className="webcare-table webcare-w-full" style={{ fontSize: '12.5px', margin: 0 }}>
                  <thead>
                    <tr>
                      <th style={{ padding: '10px 14px', width: '36%' }}>Setting / Security Rule</th>
                      <th style={{ width: '32%', padding: '10px 14px' }}>Previous Value</th>
                      <th style={{ width: '32%', padding: '10px 14px' }}>New Saved Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(selectedRecord.details?.diff || {}).map(([key, diff]) => {
                      const friendlyName = getFriendlySettingName(key);
                      const isRuleKey = friendlyName !== key;
                      return (
                        <tr key={key}>
                          <td style={{ padding: '10px 14px' }}>
                            <div style={{ fontWeight: 700, color: 'var(--webcare-text-primary)', fontSize: '12.5px', marginBottom: isRuleKey ? '2px' : '0' }}>
                              {friendlyName}
                            </div>
                            {isRuleKey && (
                              <code style={{ fontSize: '11px', color: 'var(--webcare-text-muted)' }}>
                                {key}
                              </code>
                            )}
                          </td>
                          <td style={{ color: '#f87171', background: 'rgba(239, 68, 68, 0.12)', fontFamily: 'monospace', padding: '10px 14px', wordBreak: 'break-all' }}>
                            {typeof diff.old === 'object' && diff.old !== null ? JSON.stringify(diff.old, null, 2) : String(diff.old ?? 'None')}
                          </td>
                          <td style={{ color: '#34d399', background: 'rgba(16, 185, 129, 0.12)', fontFamily: 'monospace', padding: '10px 14px', wordBreak: 'break-all' }}>
                            {typeof diff.new === 'object' && diff.new !== null ? JSON.stringify(diff.new, null, 2) : String(diff.new ?? 'None')}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Modal Footer */}
            <div
              className="webcare-modal-footer"
              style={{
                padding: '14px 24px',
                borderTop: '1px solid var(--webcare-border, rgba(255, 255, 255, 0.08))',
                background: 'var(--webcare-bg-surface-elevated, #1e293b)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}
            >
              <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                Event ID: <code>{selectedRecord.event_id}</code>
              </div>
              <button
                type="button"
                onClick={() => setSelectedRecord(null)}
                className="webcare-btn webcare-btn-secondary"
                style={{ padding: '7px 18px', fontWeight: 600, fontSize: '13px' }}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Export Options Modal */}
      {isExportModalOpen && (
        <div
          className="webcare-modal-backdrop"
          onClick={() => !isExporting && setIsExportModalOpen(false)}
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0, 0, 0, 0.65)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 999999,
            padding: '20px',
          }}
        >
          <div
            className="webcare-modal-card"
            onClick={(e) => e.stopPropagation()}
            style={{
              background: 'var(--webcare-bg-panel, #ffffff)',
              border: '1px solid var(--webcare-border, #e2e8f0)',
              borderRadius: '12px',
              maxWidth: '520px',
              width: '100%',
              boxShadow: '0 20px 40px rgba(0, 0, 0, 0.35)',
              overflow: 'hidden',
              animation: 'webcareModalIn 0.2s cubic-bezier(0.16, 1, 0.3, 1)',
            }}
          >
            {/* Modal Header */}
            <div
              style={{
                padding: '18px 24px',
                borderBottom: '1px solid var(--webcare-border, #e2e8f0)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div
                  style={{
                    width: '36px',
                    height: '36px',
                    borderRadius: '8px',
                    background: 'rgba(79, 70, 229, 0.1)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: '#4f46e5',
                  }}
                >
                  <Download size={20} />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                    Export Activity & Audit Logs
                  </h3>
                  <p style={{ margin: '2px 0 0 0', fontSize: '12px', color: 'var(--webcare-text-muted, #64748b)' }}>
                    Choose export scope, date filters, and download format
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => !isExporting && setIsExportModalOpen(false)}
                disabled={isExporting}
                style={{
                  background: 'transparent',
                  border: 'none',
                  cursor: isExporting ? 'not-allowed' : 'pointer',
                  color: 'var(--webcare-text-muted, #64748b)',
                  padding: '4px',
                }}
              >
                <X size={18} />
              </button>
            </div>

            {/* Modal Body */}
            <div style={{ padding: '22px 24px', display: 'flex', flexDirection: 'column', gap: '18px' }}>
              {/* Scope Selection */}
              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '8px' }}>
                  Select Export Scope
                </label>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '8px' }}>
                  <label
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '10px',
                      padding: '10px 14px',
                      borderRadius: '8px',
                      border: `1px solid ${exportScope === 'all' ? '#4f46e5' : 'var(--webcare-border, #e2e8f0)'}`,
                      background: exportScope === 'all' ? 'rgba(79, 70, 229, 0.05)' : 'transparent',
                      cursor: 'pointer',
                    }}
                  >
                    <input
                      type="radio"
                      name="activityExportScope"
                      checked={exportScope === 'all'}
                      onChange={() => setExportScope('all')}
                      style={{ accentColor: '#4f46e5' }}
                    />
                    <div>
                      <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>
                        All Historical Activity Logs
                      </div>
                      <div style={{ fontSize: '11.5px', color: 'var(--webcare-text-muted, #64748b)' }}>
                        Export complete multi-day audit history across all sealed partitions
                      </div>
                    </div>
                  </label>

                  <label
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '10px',
                      padding: '10px 14px',
                      borderRadius: '8px',
                      border: `1px solid ${exportScope === 'date' ? '#4f46e5' : 'var(--webcare-border, #e2e8f0)'}`,
                      background: exportScope === 'date' ? 'rgba(79, 70, 229, 0.05)' : 'transparent',
                      cursor: 'pointer',
                    }}
                  >
                    <input
                      type="radio"
                      name="activityExportScope"
                      checked={exportScope === 'date'}
                      onChange={() => setExportScope('date')}
                      style={{ accentColor: '#4f46e5' }}
                    />
                    <div>
                      <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>
                        Specific Date Logs
                      </div>
                      <div style={{ fontSize: '11.5px', color: 'var(--webcare-text-muted, #64748b)' }}>
                        Filter and download events for a chosen calendar date
                      </div>
                    </div>
                  </label>

                  <label
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '10px',
                      padding: '10px 14px',
                      borderRadius: '8px',
                      border: `1px solid ${exportScope === 'filtered' ? '#4f46e5' : 'var(--webcare-border, #e2e8f0)'}`,
                      background: exportScope === 'filtered' ? 'rgba(79, 70, 229, 0.05)' : 'transparent',
                      cursor: 'pointer',
                    }}
                  >
                    <input
                      type="radio"
                      name="activityExportScope"
                      checked={exportScope === 'filtered'}
                      onChange={() => setExportScope('filtered')}
                      style={{ accentColor: '#4f46e5' }}
                    />
                    <div>
                      <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>
                        Current Filtered Table View ({records.length} records)
                      </div>
                      <div style={{ fontSize: '11.5px', color: 'var(--webcare-text-muted, #64748b)' }}>
                        Export only currently active filtered rows from this view
                      </div>
                    </div>
                  </label>
                </div>
              </div>

              {/* Date Input (When Specific Date is selected) */}
              {exportScope === 'date' && (
                <div style={{ padding: '12px 14px', background: 'var(--webcare-bg-surface-elevated, #f8fafc)', borderRadius: '8px', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
                  <label style={{ display: 'block', fontSize: '12.5px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '6px' }}>
                    Choose Date (YYYY-MM-DD):
                  </label>
                  <input
                    type="date"
                    value={exportDate}
                    onChange={(e) => setExportDate(e.target.value)}
                    className="webcare-input"
                    style={{ width: '100%', fontSize: '13px', padding: '7px 12px' }}
                  />
                </div>
              )}

              {/* Format Selection */}
              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)', marginBottom: '8px' }}>
                  Download Format
                </label>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                  <button
                    type="button"
                    onClick={() => setExportFormat('json')}
                    style={{
                      padding: '12px',
                      borderRadius: '8px',
                      border: `2px solid ${exportFormat === 'json' ? '#4f46e5' : 'var(--webcare-border, #e2e8f0)'}`,
                      background: exportFormat === 'json' ? 'rgba(79, 70, 229, 0.05)' : 'transparent',
                      cursor: 'pointer',
                      textAlign: 'left',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 700, fontSize: '13px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                      <FileText size={16} color="#3b82f6" />
                      <span>JSON (.json)</span>
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px' }}>
                      Structured machine-readable forensic dossier
                    </div>
                  </button>

                  <button
                    type="button"
                    onClick={() => setExportFormat('csv')}
                    style={{
                      padding: '12px',
                      borderRadius: '8px',
                      border: `2px solid ${exportFormat === 'csv' ? '#4f46e5' : 'var(--webcare-border, #e2e8f0)'}`,
                      background: exportFormat === 'csv' ? 'rgba(79, 70, 229, 0.05)' : 'transparent',
                      cursor: 'pointer',
                      textAlign: 'left',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 700, fontSize: '13px', color: 'var(--webcare-text-primary, #0f172a)' }}>
                      <FileText size={16} color="#10b981" />
                      <span>CSV (.csv)</span>
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '4px' }}>
                      Spreadsheet &amp; Excel compatible table
                    </div>
                  </button>
                </div>
              </div>

              {/* Include System & Environment Diagnostics Checkbox */}
              <div
                style={{
                  padding: '12px 14px',
                  borderRadius: '8px',
                  background: includeSystemInfo ? 'rgba(79, 70, 229, 0.04)' : 'var(--webcare-bg-surface-elevated, #f8fafc)',
                  border: `1px solid ${includeSystemInfo ? '#c7d2fe' : 'var(--webcare-border, #e2e8f0)'}`,
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '12px',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease'
                }}
                onClick={() => {
                  const newVal = !includeSystemInfo;
                  setIncludeSystemInfo(newVal);
                  try {
                    localStorage.setItem('webcare_export_include_system_info', String(newVal));
                  } catch (e) {}
                }}
              >
                <input
                  type="checkbox"
                  id="activityIncludeSystemInfo"
                  checked={includeSystemInfo}
                  onChange={(e) => {
                    const newVal = e.target.checked;
                    setIncludeSystemInfo(newVal);
                    try {
                      localStorage.setItem('webcare_export_include_system_info', String(newVal));
                    } catch (e) {}
                  }}
                  style={{
                    marginTop: '2px',
                    cursor: 'pointer',
                    width: '16px',
                    height: '16px',
                    accentColor: '#4f46e5'
                  }}
                />
                <div style={{ flex: 1 }}>
                  <label
                    htmlFor="activityIncludeSystemInfo"
                    style={{
                      display: 'block',
                      fontSize: '12.5px',
                      fontWeight: 600,
                      color: 'var(--webcare-text-primary, #0f172a)',
                      cursor: 'pointer',
                      marginBottom: '2px'
                    }}
                  >
                    Include System &amp; Environment Diagnostics <span style={{ fontSize: '11px', color: '#4f46e5', fontWeight: 500 }}>(Recommended for Log Analysis)</span>
                  </label>
                  <p style={{ margin: 0, fontSize: '11.5px', color: 'var(--webcare-text-muted, #64748b)', lineHeight: 1.45 }}>
                    Embeds domain name, server real IP, Cloudflare protection status, web server / PHP versions, and active &amp; installed themes/plugins with versions. Uncheck to download raw events only.
                  </p>
                </div>
              </div>

              {/* Filename Preview Info Box */}
              <div
                style={{
                  padding: '10px 14px',
                  borderRadius: '8px',
                  background: 'var(--webcare-bg-surface-elevated, #f8fafc)',
                  border: '1px solid var(--webcare-border, #e2e8f0)',
                  fontSize: '11.5px',
                  color: 'var(--webcare-text-muted, #64748b)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                }}
              >
                <Info size={15} style={{ flexShrink: 0, color: '#4f46e5' }} />
                <span>
                  Log file will be stamped with site domain: <code>activity-logs-{exportScope === 'date' ? exportDate : new Date().toISOString().slice(0, 10)}-[time]-[domain]-[hash].{exportFormat}</code>
                </span>
              </div>
            </div>

            {/* Modal Footer */}
            <div
              style={{
                padding: '14px 24px',
                borderTop: '1px solid var(--webcare-border, #e2e8f0)',
                background: 'var(--webcare-bg-surface-elevated, #f8fafc)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'flex-end',
                gap: '10px',
              }}
            >
              <button
                type="button"
                onClick={() => setIsExportModalOpen(false)}
                disabled={isExporting}
                className="webcare-btn webcare-btn-secondary"
                style={{ padding: '8px 16px', fontSize: '13px', fontWeight: 600 }}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={executeExport}
                disabled={isExporting}
                className="webcare-btn webcare-btn-primary"
                style={{
                  padding: '8px 20px',
                  fontSize: '13px',
                  fontWeight: 600,
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  background: '#4f46e5',
                  color: '#ffffff',
                }}
              >
                {isExporting ? <RefreshCw size={14} className="webcare-spin-icon" /> : <Download size={14} />}
                <span>{isExporting ? 'Generating Export...' : `Download ${exportFormat.toUpperCase()}`}</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
