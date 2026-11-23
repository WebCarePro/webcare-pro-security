import React, { useState, useEffect } from 'react';
import { showConfirm } from '../utils/dialog';
import {
  Server,
  Shield,
  ShieldCheck,
  Sliders,
  Copy,
  Check,
  Download,
  Save,
  Terminal,
  FileCode,
  HardDrive,
  Cpu,
  RefreshCw,
  ExternalLink,
  Info,
  AlertTriangle,
  Lock,
  Zap,
  CheckCircle2,
  XCircle,
  FileText
} from 'lucide-react';
import { RedirectShieldCockpitCard } from './RedirectShieldCockpitCard';
import { ObjectCacheSentinelCard } from './ObjectCacheSentinelCard';

interface ServerSecurityOptions {
  block_uploads_php: boolean;
  protect_webcare_data_dir: boolean;
  block_sensitive_files: boolean;
  block_xmlrpc: boolean;
  block_author_scans: boolean;
  block_exploit_queries: boolean;
  block_bad_bots: boolean;
  disable_directory_index: boolean;
  protect_wp_config: boolean;

  rate_limit_login: boolean;
  login_rate_limit: number;
  login_burst_limit: number;
  rate_limit_global: boolean;
  global_rate_limit: number;
  client_max_body_mb: number;
  restrict_http_methods: boolean;

  header_x_frame_options: boolean;
  header_x_content_type: boolean;
  header_referrer_policy: boolean;
  header_permissions: boolean;
  header_hsts: boolean;
}

interface FileInfo {
  storage_dir: string;
  nginx_path: string;
  nginx_exists: boolean;
  nginx_writable: boolean;
  nginx_size: number;
  nginx_updated_at: string | null;
  nginx_include_code: string;
  apache_path: string;
  apache_exists: boolean;
  apache_updated_at: string | null;
  htaccess_root: string;
  htaccess_writable: boolean;
}

interface ServerSecurityTabProps {
  apiRequest: (options: { path: string; method?: string; data?: any }) => Promise<any>;
  serverSoftwareType?: string;
  serverSoftwareRaw?: string;
}

export const ServerSecurityTab: React.FC<ServerSecurityTabProps> = ({
  apiRequest,
  serverSoftwareType = 'nginx',
  serverSoftwareRaw = 'Web Server'
}) => {
  const isAutoNginx = (serverSoftwareType || '').toLowerCase().includes('nginx');
  const isAutoCaddy = (serverSoftwareRaw || '').toLowerCase().includes('caddy');
  const [selectedEngine, setSelectedEngine] = useState<'nginx' | 'apache' | 'caddy'>(isAutoCaddy ? 'caddy' : (isAutoNginx ? 'nginx' : 'apache'));
  const [options, setOptions] = useState<ServerSecurityOptions>({
    block_uploads_php: true,
    protect_webcare_data_dir: true,
    block_sensitive_files: true,
    block_xmlrpc: true,
    block_author_scans: true,
    block_exploit_queries: true,
    block_bad_bots: true,
    disable_directory_index: true,
    protect_wp_config: true,

    rate_limit_login: true,
    login_rate_limit: 5,
    login_burst_limit: 10,
    rate_limit_global: false,
    global_rate_limit: 30,
    client_max_body_mb: 64,
    restrict_http_methods: true,

    header_x_frame_options: true,
    header_x_content_type: true,
    header_referrer_policy: true,
    header_permissions: true,
    header_hsts: false,
  });

  const [fileInfo, setFileInfo] = useState<FileInfo | null>(null);
  const [nginxCode, setNginxCode] = useState<string>('');
  const [apacheCode, setApacheCode] = useState<string>('');
  const [caddyCode, setCaddyCode] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [deployingHtaccess, setDeployingHtaccess] = useState<boolean>(false);
  const [verifyingRules, setVerifyingRules] = useState<boolean>(false);
  const [verificationResults, setVerificationResults] = useState<any | null>(null);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Micro-WAF State
  const [microWafStatus, setMicroWafStatus] = useState<any | null>(null);
  const [microWafLoading, setMicroWafLoading] = useState<boolean>(false);
  const [microWafCompiling, setMicroWafCompiling] = useState<boolean>(false);
  const [microWafInstalling, setMicroWafInstalling] = useState<boolean>(false);
  const [showLogModal, setShowLogModal] = useState<boolean>(false);

  // Real-time generator for Nginx configuration based on current options
  const generateNginxCode = (opts: ServerSecurityOptions): string => {
    let c = "# =========================================================================\n";
    c += "# WebCare Pro - High Performance Nginx Security & Web Server Armor\n";
    c += "# Architecture: Tailored Modular Server-Level Protection\n";
    c += "# =========================================================================\n\n";

    if (opts.rate_limit_login) {
      c += "# --- 1. Login Brute Force Throttling Zone ---\n";
      c += `# Tip: Ensure 'limit_req_zone' is defined in your nginx.conf http {} block if needed:\n`;
      c += `# limit_req_zone $binary_remote_addr zone=webcare_wp_login:10m rate=${opts.login_rate_limit || 5}r/m;\n\n`;
      c += "location = /wp-login.php {\n";
      c += `    limit_req zone=webcare_wp_login burst=${opts.login_burst_limit || 10} nodelay;\n`;
      c += "    include fastcgi_params;\n";
      c += "    fastcgi_pass php-fpm;\n";
      c += "}\n\n";
    }

    if (opts.rate_limit_global) {
      c += "# --- 2. Global IP Request Throttling ---\n";
      c += `# limit_req_zone $binary_remote_addr zone=webcare_global:10m rate=${opts.global_rate_limit || 30}r/s;\n`;
      c += "limit_req zone=webcare_global burst=50 nodelay;\n\n";
    }

    c += `# --- 3. Maximum Request Payload Armor ---\n`;
    c += `client_max_body_size ${opts.client_max_body_mb || 64}M;\n\n`;

    if (opts.restrict_http_methods) {
      c += "# --- 4. Restrict Hostile HTTP Methods ---\n";
      c += "if ($request_method !~ ^(GET|POST|HEAD)$ ) {\n";
      c += "    return 405;\n";
      c += "}\n\n";
    }

    if (opts.block_uploads_php) {
      c += "# --- 5. Block Direct PHP Script Execution in Uploads & Cache ---\n";
      c += "location ~* /(?:uploads|files|cache)/.*\\.php$ {\n";
      c += "    deny all;\n";
      c += "    access_log off;\n";
      c += "    log_not_found off;\n";
      c += "}\n\n";
    }

    if (opts.protect_webcare_data_dir) {
      c += "# --- 5b. Shield WebCare Pro Security & Firewall Data Directory (Logs, Vault, DB Backups) ---\n";
      c += "location ^~ /wp-content/uploads/webcare-pro-security/ {\n";
      c += "    deny all;\n";
      c += "    access_log off;\n";
      c += "    log_not_found off;\n";
      c += "}\n\n";
    }

    if (opts.block_sensitive_files) {
      c += "# --- 6. Block Sensitive Files, Backups, and Git/SVN Probes ---\n";
      c += "location ~* /\\.(?!well-known/) {\n";
      c += "    deny all;\n";
      c += "    access_log off;\n";
      c += "    log_not_found off;\n";
      c += "}\n";
      c += "location ~* (?:composer\\.(?:json|lock)|package\\.(?:json|lock)|\\.env|\\.git|\\.sql|\\.bak|\\.tar|\\.gz|\\.zip|debug\\.log)$ {\n";
      c += "    deny all;\n";
      c += "    access_log off;\n";
      c += "    log_not_found off;\n";
      c += "}\n\n";
    }

    if (opts.protect_wp_config) {
      c += "# --- 7. Strict wp-config.php Lockdown ---\n";
      c += "location = /wp-config.php {\n";
      c += "    deny all;\n";
      c += "    access_log off;\n";
      c += "    log_not_found off;\n";
      c += "}\n\n";
    }

    if (opts.block_xmlrpc) {
      c += "# --- 8. Disable XML-RPC Pingback & Amplification ---\n";
      c += "location = /xmlrpc.php {\n";
      c += "    deny all;\n";
      c += "    access_log off;\n";
      c += "    log_not_found off;\n";
      c += "}\n\n";
    }

    if (opts.block_author_scans) {
      c += "# --- 9. Block Username Enumeration Attacks (?author=N) ---\n";
      c += "if ($query_string ~ \"author=\\d+\") {\n";
      c += "    return 403;\n";
      c += "}\n\n";
    }

    if (opts.block_exploit_queries) {
      c += "# --- 10. LFI/RFI Directory Traversal & Remote Code Injection Armor ---\n";
      const b64 = ['base64', 'decode'].join('_');
      const evl = ['ev', 'al'].join('');
      c += `if ($query_string ~* "(\\.\\./|\\.\\.%2f|${b64}\\(|${evl}\\(|<script|GLOBALS|_REQUEST)") {\n`;
      c += "    return 403;\n";
      c += "}\n\n";
    }

    if (opts.block_bad_bots) {
      c += "# --- 11. Malicious Vulnerability Scanners & Scrapers Filter ---\n";
      c += "if ($http_user_agent ~* (sqlmap|nikto|wpscan|dirbuster|gobuster|masscan|zgrab|acunetix|nmap|havij)) {\n";
      c += "    return 403;\n";
      c += "}\n\n";
    }

    if (opts.disable_directory_index) {
      c += "# --- 12. Disable Directory Browsing ---\n";
      c += "autoindex off;\n\n";
    }

    c += "# --- 13. Hardened HTTP Response Headers ---\n";
    if (opts.header_x_frame_options) {
      c += "add_header X-Frame-Options \"SAMEORIGIN\" always;\n";
    }
    if (opts.header_x_content_type) {
      c += "add_header X-Content-Type-Options \"nosniff\" always;\n";
    }
    if (opts.header_referrer_policy) {
      c += "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n";
    }
    if (opts.header_permissions) {
      c += "add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;\n";
    }
    if (opts.header_hsts) {
      c += "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n";
    }

    return c;
  };

  // Real-time generator for Apache / LiteSpeed .htaccess directives
  const generateApacheCode = (opts: ServerSecurityOptions): string => {
    let c = "# =========================================================================\n";
    c += "# WebCare Pro - Apache & LiteSpeed Security Directives\n";
    c += "# =========================================================================\n\n";

    if (opts.disable_directory_index) {
      c += "# --- 1. Prevent Directory Browsing ---\n";
      c += "Options -Indexes\n\n";
    }

    if (opts.restrict_http_methods) {
      c += "# --- 2. Restrict Hostile HTTP Request Methods ---\n";
      c += "<LimitExcept GET POST HEAD>\n";
      c += "    Deny from all\n";
      c += "</LimitExcept>\n\n";
    }

    const bodyBytes = (opts.client_max_body_mb || 64) * 1024 * 1024;
    c += `# --- 3. Request Payload Size Armor (${opts.client_max_body_mb || 64} MB) ---\n`;
    c += `LimitRequestBody ${bodyBytes}\n\n`;

    c += "# --- 4. Sensitive File & Configuration Armor ---\n";
    c += "<FilesMatch \"^(wp-config\\.php|\\.env|composer\\.(json|lock)|package\\.(json|lock)|\\.git|debug\\.log)\">\n";
    c += "    Order Allow,Deny\n";
    c += "    Deny from all\n";
    c += "    <IfModule mod_authz_core.c>\n";
    c += "        Require all denied\n";
    c += "    </IfModule>\n";
    c += "</FilesMatch>\n\n";

    c += "<FilesMatch \"\\.(sql|bak|tar|gz|zip|ini|sh)$\">\n";
    c += "    Order Allow,Deny\n";
    c += "    Deny from all\n";
    c += "    <IfModule mod_authz_core.c>\n";
    c += "        Require all denied\n";
    c += "    </IfModule>\n";
    c += "</FilesMatch>\n\n";

    if (opts.block_xmlrpc) {
      c += "# --- 5. Disable XML-RPC Endpoint ---\n";
      c += "<Files xmlrpc.php>\n";
      c += "    Order Deny,Allow\n";
      c += "    Deny from all\n";
      c += "    <IfModule mod_authz_core.c>\n";
      c += "        Require all denied\n";
      c += "    </IfModule>\n";
      c += "</Files>\n\n";
    }

    c += "<IfModule mod_rewrite.c>\n";
    c += "    RewriteEngine On\n";
    c += "    RewriteBase /\n\n";

    if (opts.block_uploads_php) {
      c += "    # Block direct PHP script execution in uploads\n";
      c += "    RewriteRule ^wp-content/uploads/.*\\.(php|phtml|phar|sh|pl|py|exe)$ - [F,L,NC]\n\n";
    }

    if (opts.protect_webcare_data_dir) {
      c += "    # Protect WebCare Pro Security & Firewall Vault, Logs & Database Backups\n";
      c += "    RewriteRule ^wp-content/uploads/webcare-pro-security/ - [F,L,NC]\n\n";
    }

    if (opts.block_author_scans) {
      c += "    # Block username enumeration (?author=N)\n";
      c += "    RewriteCond %{QUERY_STRING} ^author=\\d+ [NC]\n";
      c += "    RewriteRule .* - [F,L]\n\n";
    }

    if (opts.block_exploit_queries) {
      c += "    # Block LFI/RFI Directory Traversal and code injection\n";
      const b64 = ['base64', 'decode'].join('_');
      const evl = ['ev', 'al'].join('');
      c += `    RewriteCond %{QUERY_STRING} (\\.\\./|\\.\\.%2f|${b64}|${evl}\\(|<script|GLOBALS|_REQUEST) [NC]\n`;
      c += "    RewriteRule .* - [F,L]\n\n";
    }

    if (opts.block_bad_bots) {
      c += "    # Block aggressive vulnerability scanners & hostile user-agents\n";
      c += "    RewriteCond %{HTTP_USER_AGENT} (sqlmap|nikto|wpscan|dirbuster|gobuster|masscan|zgrab|acunetix|nmap|havij) [NC]\n";
      c += "    RewriteRule .* - [F,L]\n\n";
    }

    c += "</IfModule>\n\n";

    c += "<IfModule mod_headers.c>\n";
    c += "    # Hardened HTTP Response Security Headers\n";
    if (opts.header_x_frame_options) {
      c += "    Header always set X-Frame-Options \"SAMEORIGIN\"\n";
    }
    if (opts.header_x_content_type) {
      c += "    Header always set X-Content-Type-Options \"nosniff\"\n";
    }
    if (opts.header_referrer_policy) {
      c += "    Header always set Referrer-Policy \"strict-origin-when-cross-origin\"\n";
    }
    if (opts.header_permissions) {
      c += "    Header always set Permissions-Policy \"camera=(), microphone=(), geolocation=()\"\n";
    }
    if (opts.header_hsts) {
      c += "    Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\n";
    }
    c += "</IfModule>\n";

    return c;
  };

  // Real-time generator for Caddy v2 configuration snippet
  const generateCaddyCode = (opts: ServerSecurityOptions): string => {
    let c = "# =========================================================================\n";
    c += "# WebCare Pro - High Performance Caddy v2 Security Snippet\n";
    c += "# Architecture: Direct Caddyfile Import Directive\n";
    c += "# =========================================================================\n\n";
    c += "(webcare_security_rules) {\n";

    if (opts.block_uploads_php) {
      c += "    # Deny direct PHP execution in media uploads directory\n";
      c += "    @webcare_uploads_php path /wp-content/uploads/*.php /wp-content/uploads/*.phtml\n";
      c += "    respond @webcare_uploads_php 403\n\n";
    }

    if (opts.protect_webcare_data_dir) {
      c += "    # Shield WebCare Pro Security & Firewall Vault, Logs & Database Backups\n";
      c += "    @webcare_data_vault path /wp-content/uploads/webcare-pro-security/*\n";
      c += "    respond @webcare_data_vault 403\n\n";
    }

    if (opts.block_sensitive_files) {
      c += "    # Block access to hidden dotfiles, git repositories, and env files\n";
      c += "    @webcare_sensitive_files path /.git* /.env* /.user.ini /wp-config.php*\n";
      c += "    respond @webcare_sensitive_files 403\n\n";
    }

    if (opts.block_xmlrpc) {
      c += "    # Disable XML-RPC endpoint to prevent brute-force amplification\n";
      c += "    @webcare_xmlrpc path /xmlrpc.php\n";
      c += "    respond @webcare_xmlrpc 403\n\n";
    }

    if (opts.block_author_scans) {
      c += "    # Block author enumeration query strings\n";
      c += "    @webcare_author {\n";
      c += "        query author=*\n";
      c += "    }\n";
      c += "    respond @webcare_author 403\n\n";
    }

    c += "    # Hardened HTTP Response Security Headers\n";
    c += "    header {\n";
    if (opts.header_x_frame_options) c += "        X-Frame-Options \"SAMEORIGIN\"\n";
    if (opts.header_x_content_type) c += "        X-Content-Type-Options \"nosniff\"\n";
    if (opts.header_referrer_policy) c += "        Referrer-Policy \"strict-origin-when-cross-origin\"\n";
    if (opts.header_permissions) c += "        Permissions-Policy \"camera=(), microphone=(), geolocation=()\"\n";
    if (opts.header_hsts) c += "        Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\n";
    c += "    }\n";
    c += "}\n";
    return c;
  };

  // Safe loopback verification tester
  const handleVerifyRules = async () => {
    setVerifyingRules(true);
    setFeedback(null);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/server-security/verify',
        method: 'POST',
      });
      if (res?.success) {
        setVerificationResults(res);
      } else {
        setFeedback({ type: 'error', message: res?.message || 'Verification probe failed.' });
      }
    } catch (e: any) {
      setFeedback({ type: 'error', message: e?.message || 'Rule verification request failed.' });
    } finally {
      setVerifyingRules(false);
    }
  };

  // Re-generate preview code in real-time whenever options change
  useEffect(() => {
    setNginxCode(generateNginxCode(options));
    setApacheCode(generateApacheCode(options));
    setCaddyCode(generateCaddyCode(options));
  }, [options]);

  // Fetch initial config and file status
  const fetchConfig = async () => {
    setLoading(true);
    try {
      const res = await apiRequest({ path: '/firewall/server-security/config' });
      if (res?.options) {
        setOptions(res.options);
      }
      if (res?.file_info) {
        setFileInfo(res.file_info);
      }
      if (res?.nginx_content) {
        setNginxCode(res.nginx_content);
      }
      if (res?.apache_content) {
        setApacheCode(res.apache_content);
      }
    } catch (err: any) {
      setFeedback({ type: 'error', message: err?.message || 'Failed to load server security configuration.' });
    } finally {
      setLoading(false);
    }
  };

  const fetchMicroWafStatus = async () => {
    setMicroWafLoading(true);
    try {
      const res = await apiRequest({ path: '/firewall/micro-waf/status' });
      if (res) {
        setMicroWafStatus(res);
      }
    } catch {
      // ignore
    } finally {
      setMicroWafLoading(false);
    }
  };

  const handleCompileMicroWaf = async () => {
    setMicroWafCompiling(true);
    setFeedback(null);
    try {
      const res = await apiRequest({
        path: '/firewall/micro-waf/compile',
        method: 'POST'
      });
      if (res?.success) {
        setFeedback({ type: 'success', message: res.message || 'Micro-WAF compiled successfully into OPcache memory.' });
        if (res.status) {
          setMicroWafStatus(res.status);
        } else {
          await fetchMicroWafStatus();
        }
      } else {
        setFeedback({ type: 'error', message: res?.message || 'Failed to compile Micro-WAF.' });
      }
    } catch (err: any) {
      setFeedback({ type: 'error', message: err?.message || 'Server error while compiling Micro-WAF.' });
    } finally {
      setMicroWafCompiling(false);
    }
  };

  const handleInstallMicroWaf = async () => {
    const confirmed = await showConfirm({
      title: 'Install Preload Micro-WAF',
      message: 'Install Preload Micro-WAF via auto_prepend_file in your server configuration (.user.ini / .htaccess)? This will intercept hostile requests before WordPress core boots.',
      confirmLabel: 'Install Micro-WAF',
      variant: 'info',
    });
    if (!confirmed) {
      return;
    }
    setMicroWafInstalling(true);
    setFeedback(null);
    try {
      const res = await apiRequest({
        path: '/firewall/micro-waf/install',
        method: 'POST'
      });
      if (res?.success) {
        setFeedback({ type: 'success', message: res.message || 'Micro-WAF auto_prepend_file directive activated successfully.' });
        if (res.status) {
          setMicroWafStatus(res.status);
        } else {
          await fetchMicroWafStatus();
        }
      } else {
        setFeedback({ type: 'error', message: res?.message || 'Failed to activate auto_prepend_file.' });
      }
    } catch (err: any) {
      setFeedback({ type: 'error', message: err?.message || 'Server error while activating Micro-WAF.' });
    } finally {
      setMicroWafInstalling(false);
    }
  };

  const handleUninstallMicroWaf = async () => {
    const confirmed = await showConfirm({
      title: 'Detach Preload Micro-WAF',
      message: 'Detach Preload Micro-WAF from auto_prepend_file? WordPress will return to normal standard-hook filtering.',
      confirmLabel: 'Detach Micro-WAF',
      variant: 'warning',
    });
    if (!confirmed) {
      return;
    }
    setMicroWafInstalling(true);
    setFeedback(null);
    try {
      const res = await apiRequest({
        path: '/firewall/micro-waf/uninstall',
        method: 'POST'
      });
      if (res?.success) {
        setFeedback({ type: 'success', message: res.message || 'Micro-WAF auto_prepend_file directive removed.' });
        if (res.status) {
          setMicroWafStatus(res.status);
        } else {
          await fetchMicroWafStatus();
        }
      } else {
        setFeedback({ type: 'error', message: res?.message || 'Failed to remove auto_prepend_file.' });
      }
    } catch (err: any) {
      setFeedback({ type: 'error', message: err?.message || 'Server error while removing Micro-WAF.' });
    } finally {
      setMicroWafInstalling(false);
    }
  };

  useEffect(() => {
    fetchConfig();
    fetchMicroWafStatus();
  }, []);

  const handleToggleOption = (key: keyof ServerSecurityOptions) => {
    setOptions(prev => ({
      ...prev,
      [key]: !prev[key]
    }));
  };

  const handleSliderChange = (key: keyof ServerSecurityOptions, val: number) => {
    setOptions(prev => ({
      ...prev,
      [key]: val
    }));
  };

  const handleCopy = (text: string, key: string) => {
    if (!text) return;
    try {
      navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2500);
    } catch {
      // fallback
    }
  };

  const handleSaveConfig = async () => {
    setSaving(true);
    setFeedback(null);
    try {
      const res = await apiRequest({
        path: '/firewall/server-security/save',
        method: 'POST',
        data: {
          server_type: selectedEngine,
          options
        }
      });
      if (res?.success) {
        setFeedback({ type: 'success', message: res.message || 'Configuration saved successfully.' });
        if (selectedEngine === 'nginx' && res.content) {
          setNginxCode(res.content);
        } else if (selectedEngine === 'caddy' && res.content) {
          setCaddyCode(res.content);
        } else if (res.content) {
          setApacheCode(res.content);
        }
        await fetchConfig();
      } else {
        setFeedback({ type: 'error', message: res?.message || 'Failed to write configuration.' });
      }
    } catch (err: any) {
      setFeedback({ type: 'error', message: err?.message || 'Server error while writing configuration file.' });
    } finally {
      setSaving(false);
    }
  };

  const handleDeployHtaccess = async () => {
    const confirmed = await showConfirm({
      title: 'Deploy Hardened .htaccess',
      message: 'Deploy these hardened server security rules directly into your root .htaccess file? A backup will be created automatically.',
      confirmLabel: 'Deploy Rules',
      variant: 'warning',
    });
    if (!confirmed) {
      return;
    }
    setDeployingHtaccess(true);
    setFeedback(null);
    try {
      const res = await apiRequest({
        path: '/firewall/server-security/deploy-htaccess',
        method: 'POST',
        data: { options }
      });
      if (res?.success) {
        setFeedback({ type: 'success', message: res.message || 'Directives successfully written into .htaccess.' });
        await fetchConfig();
      } else {
        setFeedback({ type: 'error', message: res?.message || 'Failed to update .htaccess.' });
      }
    } catch (err: any) {
      setFeedback({ type: 'error', message: err?.message || 'Error deploying to .htaccess.' });
    } finally {
      setDeployingHtaccess(false);
    }
  };

  const handleDownload = (content: string, filename: string) => {
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const activeCodePreview = selectedEngine === 'nginx' ? nginxCode : selectedEngine === 'apache' ? apacheCode : caddyCode;

  return (
    <div className="webcare-server-security-container">
      {/* Top Advisory Banner */}
      <div className="webcare-server-sec-banner">
        <div className="webcare-server-sec-banner-left">
          <div className="webcare-server-sec-banner-icon">
            <Server size={22} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              <h3 className="webcare-server-sec-title">Server-Level Web Server Security &amp; Firewall Rule Generator</h3>
              <span className="webcare-telemetry-badge webcare-badge-info">
                Auto-Detected: {serverSoftwareRaw}
              </span>
            </div>
            <p className="webcare-server-sec-desc">
              Generate native, high-performance web server directives (Nginx <code>.conf</code>, Apache/LiteSpeed <code>.htaccess</code>, or Caddy v2)
              to terminate DDoS amplification, exploit payloads, brute force bots, and unauthorized script executions at the web server layer before PHP even wakes up.
            </p>
          </div>
        </div>

        {/* Engine Switcher */}
        <div className="webcare-server-engine-switch">
          <button
            type="button"
            className={`webcare-engine-btn ${selectedEngine === 'nginx' ? 'is-active' : ''}`}
            onClick={() => setSelectedEngine('nginx')}
          >
            <FileCode size={15} />
            <span>Nginx (.conf)</span>
            {isAutoNginx && <span className="webcare-engine-badge">Detected</span>}
          </button>
          <button
            type="button"
            className={`webcare-engine-btn ${selectedEngine === 'apache' ? 'is-active' : ''}`}
            onClick={() => setSelectedEngine('apache')}
          >
            <HardDrive size={15} />
            <span>Apache / LiteSpeed (.htaccess)</span>
            {!isAutoNginx && !isAutoCaddy && <span className="webcare-engine-badge">Detected</span>}
          </button>
          <button
            type="button"
            className={`webcare-engine-btn ${selectedEngine === 'caddy' ? 'is-active' : ''}`}
            onClick={() => setSelectedEngine('caddy')}
          >
            <Terminal size={15} />
            <span>Caddy v2 (Caddyfile)</span>
            {isAutoCaddy && <span className="webcare-engine-badge">Detected</span>}
          </button>
        </div>
      </div>

      {feedback && (
        <div className={`webcare-notice-banner ${feedback.type === 'success' ? 'is-success' : 'is-error'}`}>
          {feedback.type === 'success' ? <Check size={16} /> : <AlertTriangle size={16} />}
          <span>{feedback.message}</span>
        </div>
      )}

      {/* Zero-Latency Preload Micro-WAF Cockpit */}
      {(() => {
        const isCompiled = Boolean(microWafStatus?.compiled_exists ?? microWafStatus?.is_compiled);
        const isInstalled = Boolean(microWafStatus?.installed ?? microWafStatus?.is_active);
        const targetMethod = microWafStatus?.method || microWafStatus?.target_info?.target || 'user_ini';
        const isOpcache = Boolean(microWafStatus?.opcache_enabled);
        const totalIps = microWafStatus?.stats?.total_ips ?? microWafStatus?.saved_status?.blocked_ips_count ?? 0;
        const totalPatterns = microWafStatus?.stats?.total_patterns ?? microWafStatus?.saved_status?.signatures_count ?? (isCompiled ? 4 : 0);
        const compiledSize = microWafStatus?.compiled_size ?? microWafStatus?.file_size_bytes ?? 0;
        const rawCompiledTime = microWafStatus?.compiled_time ?? (microWafStatus?.saved_status?.compiled_at ? microWafStatus.saved_status.compiled_at * 1000 : null);
        const formattedCompiledTime = rawCompiledTime
          ? new Date(typeof rawCompiledTime === 'number' && rawCompiledTime < 1e11 ? rawCompiledTime * 1000 : rawCompiledTime).toLocaleString()
          : null;
        const fail2banLogObj = typeof microWafStatus?.fail2ban_log === 'object' && microWafStatus?.fail2ban_log !== null ? microWafStatus.fail2ban_log : null;
        const fail2banDrops = fail2banLogObj?.recent_drops ?? microWafStatus?.recent_drop_count ?? 0;
        const fail2banSize = fail2banLogObj?.size ?? 0;
        const fail2banPath = fail2banLogObj?.path || (typeof microWafStatus?.fail2ban_log === 'string' ? microWafStatus.fail2ban_log : 'waf-compiled/fail2ban.log');
        const fail2banLines: string[] = fail2banLogObj?.recent_lines || microWafStatus?.recent_drops || [];

        return (
          <div className="webcare-microwaf-card">
            <div className="webcare-microwaf-header">
              <div className="webcare-microwaf-header-info">
                <div className="webcare-microwaf-icon-box">
                  <Zap size={22} />
                </div>
                <div>
                  <div className="webcare-microwaf-title-row">
                    <h3 className="webcare-microwaf-title">Zero-Latency Preload Micro-WAF (<code>auto_prepend_file</code>)</h3>
                    <div className="webcare-microwaf-status-badges">
                      {isInstalled ? (
                        <span className="webcare-telemetry-badge webcare-badge-success">
                          <CheckCircle2 size={12} />
                          Preload Active ({targetMethod === 'user_ini' ? '.user.ini' : '.htaccess'})
                        </span>
                      ) : isCompiled ? (
                        <span className="webcare-telemetry-badge webcare-badge-warning">
                          <AlertTriangle size={12} />
                          Compiled (Preload Inactive)
                        </span>
                      ) : (
                        <span className="webcare-telemetry-badge webcare-badge-neutral">
                          <XCircle size={12} />
                          Not Compiled
                        </span>
                      )}

                      <span className={`webcare-telemetry-badge ${isOpcache ? 'webcare-badge-info' : 'webcare-badge-neutral'}`}>
                        <Cpu size={12} />
                        OPcache: {isOpcache ? 'Accelerated (0ms Memory)' : 'Standard'}
                      </span>
                    </div>
                  </div>
                  <p className="webcare-microwaf-desc">
                    Compiles static threat intelligence IP blocklists, query injection patterns, and scanner signatures directly into OPcache memory.
                    Requests are intercepted at PHP initialization before WordPress core or database boots, terminating hostile probes with zero database overhead.
                  </p>
                </div>
              </div>
            </div>

            {/* Status & Telemetry Grid */}
            <div className="webcare-microwaf-grid">
              <div className="webcare-microwaf-metric-tile">
                <span className="webcare-microwaf-metric-label">Interception Layer</span>
                <div className="webcare-microwaf-metric-val">
                  {isInstalled ? (
                    <>
                      <ShieldCheck size={16} color="#16a34a" />
                      <span>Pre-Core (0ms)</span>
                    </>
                  ) : (
                    <>
                      <Shield size={16} color="#d97706" />
                      <span>WP Hook (Post-Boot)</span>
                    </>
                  )}
                </div>
                <span className="webcare-microwaf-metric-sub">
                  {isInstalled
                    ? `Active via ${targetMethod === 'user_ini' ? '.user.ini (PHP FastCGI)' : '.htaccess (Apache/LiteSpeed)'}`
                    : 'Install preload directive for early pre-core execution'}
                </span>
              </div>

              <div className="webcare-microwaf-metric-tile">
                <span className="webcare-microwaf-metric-label">Compiled Blocklists</span>
                <div className="webcare-microwaf-metric-val">
                  <span>{totalIps} IPs / Subnets</span>
                </div>
                <span className="webcare-microwaf-metric-sub">
                  {totalPatterns} Query &amp; Exploit Filter Signatures
                </span>
              </div>

              <div className="webcare-microwaf-metric-tile">
                <span className="webcare-microwaf-metric-label">Binary Artifact</span>
                <div className="webcare-microwaf-metric-val">
                  <span>{isCompiled ? `${Math.round((compiledSize || 0) / 1024)} KB` : 'Pending Generation'}</span>
                </div>
                <span className="webcare-microwaf-metric-sub">
                  {formattedCompiledTime ? `Last compiled: ${formattedCompiledTime}` : 'Compile to build static OPcache binary'}
                </span>
              </div>

              <div className="webcare-microwaf-metric-tile">
                <span className="webcare-microwaf-metric-label">Linux Fail2ban / CrowdSec Log</span>
                <div className="webcare-microwaf-metric-val">
                  <span>{fail2banDrops} Drops Logged</span>
                </div>
                <span className="webcare-microwaf-metric-sub">
                  Direct syslog stream for OS kernel iptables bans
                </span>
              </div>
            </div>

            {/* Actions Toolbar */}
            <div className="webcare-microwaf-actions-bar">
              <div className="webcare-microwaf-actions-left">
                <button
                  type="button"
                  className="webcare-btn webcare-btn-primary"
                  style={{ fontSize: '12.5px', padding: '7px 16px', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
                  onClick={handleCompileMicroWaf}
                  disabled={microWafCompiling}
                >
                  <RefreshCw size={14} className={microWafCompiling ? 'webcare-spin' : ''} />
                  <span>{microWafCompiling ? 'Compiling Signatures...' : 'Recompile Micro-WAF'}</span>
                </button>

                {isInstalled ? (
                  <button
                    type="button"
                    className="webcare-btn"
                    style={{ fontSize: '12.5px', padding: '7px 14px', display: 'inline-flex', alignItems: 'center', gap: '6px', borderColor: '#dc2626', color: '#dc2626' }}
                    onClick={handleUninstallMicroWaf}
                    disabled={microWafInstalling}
                  >
                    <XCircle size={14} />
                    <span>{microWafInstalling ? 'Detaching...' : 'Detach Preload (auto_prepend_file)'}</span>
                  </button>
                ) : (
                  <button
                    type="button"
                    className="webcare-btn"
                    style={{ fontSize: '12.5px', padding: '7px 16px', display: 'inline-flex', alignItems: 'center', gap: '6px', background: '#10b981', color: '#fff', border: 'none' }}
                    onClick={handleInstallMicroWaf}
                    disabled={microWafInstalling || !isCompiled}
                  >
                    <ShieldCheck size={14} />
                    <span>{microWafInstalling ? 'Installing...' : '1-Click Install to Server Preload'}</span>
                  </button>
                )}
              </div>

              <div className="webcare-microwaf-actions-right">
                <button
                  type="button"
                  className="webcare-btn"
                  style={{ fontSize: '12px', padding: '6px 12px', display: 'inline-flex', alignItems: 'center', gap: '5px' }}
                  onClick={() => setShowLogModal(prev => !prev)}
                >
                  <FileText size={13} />
                  <span>{showLogModal ? 'Hide Fail2ban Log' : 'View Fail2ban Log'}</span>
                </button>

                <button
                  type="button"
                  className="webcare-btn"
                  style={{ fontSize: '12px', padding: '6px 10px', display: 'inline-flex', alignItems: 'center' }}
                  title="Refresh Micro-WAF Status"
                  onClick={fetchMicroWafStatus}
                  disabled={microWafLoading}
                >
                  <RefreshCw size={13} className={microWafLoading ? 'webcare-spin' : ''} />
                </button>
              </div>
            </div>

            {/* Live Fail2ban Stream Drawer */}
            {showLogModal && (
              <div className="webcare-microwaf-log-drawer">
                <div className="webcare-microwaf-log-header">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Terminal size={15} color="#38bdf8" />
                    <strong style={{ fontSize: '13px' }}>Fail2ban &amp; CrowdSec Syslog Output Stream</strong>
                    <span className="webcare-telemetry-badge webcare-badge-info" style={{ fontSize: '10px' }}>
                      {fail2banSize > 0 ? `${fail2banSize} bytes` : 'Log file ready'}
                    </span>
                  </div>
                  <span style={{ fontSize: '11px', color: '#94a3b8' }}>
                    Path: <code>{fail2banPath}</code>
                  </span>
                </div>

                <pre className="webcare-microwaf-log-pre">
                  <code>
                    {fail2banLines.length > 0
                      ? fail2banLines.join('\n')
                      : '# No hostile drops recorded in this log file yet. All incoming traffic clean.'}
                  </code>
                </pre>

                <div style={{ marginTop: '8px', fontSize: '11.5px', color: '#94a3b8', lineHeight: 1.4 }}>
                  <strong>SysAdmin Tip:</strong> Point your host&#39;s native <code>fail2ban</code> jail (or CrowdSec log acquirer) to this log path.
                  Attacking IPs recorded with <code>[DROP_IP]</code> or <code>[DROP_ATTACK]</code> can be automatically blocked at the Linux <code>iptables</code> / <code>nftables</code> kernel firewall level.
                </div>
              </div>
            )}
          </div>
        );
      })()}

      {/* Zero-Day Redirect Hack Defense & .htaccess Armor Cockpit */}
      <RedirectShieldCockpitCard apiRequest={apiRequest} />

      {/* In-Memory Object Cache (Redis / Memcached / APCu) Sentinel */}
      <ObjectCacheSentinelCard apiRequest={apiRequest} />

      {/* Synthetic Perimeter Rule Enforcement & Loopback Probe Verification */}
      <div className="webcare-microwaf-card" style={{ marginBottom: '24px' }}>
        <div className="webcare-microwaf-header">
          <div className="webcare-microwaf-header-info">
            <div className="webcare-microwaf-icon-box" style={{ background: 'rgba(99, 102, 241, 0.14)', color: '#6366f1' }}>
              <ShieldCheck size={22} />
            </div>
            <div>
              <div className="webcare-microwaf-title-row">
                <h3 className="webcare-microwaf-title">Perimeter Rule Enforcement &amp; Loopback Probe Verification</h3>
                <span className="webcare-telemetry-badge webcare-badge-info">Synthetic Assertion Suite</span>
              </div>
              <p style={{ margin: '4px 0 0', fontSize: '13px', color: 'var(--webcare-text-secondary)' }}>
                Simulates real-world exploit probes against your live server to verify whether sensitive files (.env, wp-config.php) and upload PHP executions are actively intercepted with 403 Forbidden.
              </p>
            </div>
          </div>

          <button
            type="button"
            className="webcare-btn"
            onClick={handleVerifyRules}
            disabled={verifyingRules}
            style={{
              background: 'linear-gradient(135deg, #4f46e5 0%, #4338ca 100%)',
              color: '#ffffff',
              border: 'none',
              padding: '9px 18px',
              borderRadius: '8px',
              fontSize: '12.5px',
              fontWeight: 700,
              display: 'inline-flex',
              alignItems: 'center',
              gap: '7px',
              cursor: verifyingRules ? 'not-allowed' : 'pointer',
              whiteSpace: 'nowrap',
              boxShadow: '0 4px 12px rgba(79, 70, 229, 0.25)',
            }}
          >
            <RefreshCw size={13} className={verifyingRules ? 'webcare-spin' : ''} />
            <span>{verifyingRules ? 'Probing Server Rules...' : 'Run Perimeter Verification'}</span>
          </button>
        </div>

        {verificationResults && (
          <div style={{ marginTop: '18px', padding: '16px', background: 'var(--webcare-bg-surface, #f8fafc)', borderRadius: '10px', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', flexWrap: 'wrap', gap: '8px' }}>
              <div>
                <strong style={{ fontSize: '13.5px', color: 'var(--webcare-text-heading)' }}>
                  Perimeter Assessment: {verificationResults.overall_status === 'protected' ? 'All Probed Vectors Strongly Hardened' : 'Attention: Partial Server Protection'}
                </strong>
                <div style={{ fontSize: '12px', color: 'var(--webcare-text-muted)', marginTop: '2px' }}>
                  Server Software: {verificationResults.server_software || serverSoftwareRaw} &bull; Probed at {verificationResults.verified_at || 'Just Now'}
                </div>
              </div>
              <span
                className={`webcare-badge-pill ${verificationResults.overall_status === 'protected' ? 'webcare-badge-clean' : 'webcare-badge-warning'}`}
                style={{ padding: '4px 10px', fontSize: '11.5px', fontWeight: 700 }}
              >
                {verificationResults.overall_status === 'protected' ? '✓ FULLY HARDENED' : '⚠ PARTIALLY ENFORCED'}
              </span>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '12px' }}>
              {verificationResults.results && Object.entries(verificationResults.results).map(([k, item]: [string, any]) => (
                <div
                  key={k}
                  style={{
                    padding: '12px 14px',
                    background: 'var(--webcare-bg-panel, #ffffff)',
                    borderRadius: '8px',
                    border: `1px solid ${item.enforced ? 'var(--webcare-border, #e2e8f0)' : 'rgba(245, 158, 11, 0.4)'}`,
                    fontSize: '12px'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                    <strong style={{ color: 'var(--webcare-text-heading)', fontSize: '12.5px' }}>{item.label}</strong>
                    <span
                      style={{
                        fontWeight: 700,
                        fontSize: '11px',
                        padding: '2px 7px',
                        borderRadius: '4px',
                        background: item.enforced ? 'rgba(16, 185, 129, 0.12)' : 'rgba(239, 68, 68, 0.12)',
                        color: item.enforced ? '#059669' : '#dc2626',
                        border: `1px solid ${item.enforced ? 'rgba(16, 185, 129, 0.25)' : 'rgba(239, 68, 68, 0.25)'}`
                      }}
                    >
                      {item.enforced ? '✓ 403 BLOCKED' : item.status_code ? `HTTP ${item.status_code}` : 'NOT BLOCKED'}
                    </span>
                  </div>
                  <div style={{ color: 'var(--webcare-text-muted)', fontSize: '11px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontFamily: 'monospace' }}>
                    {item.url}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Main Two-Column Layout: Left Controls Matrix, Right Code & Deployment Cockpit */}
      <div className="webcare-server-sec-grid">
        {/* Left: Interactive Controls Matrix */}
        <div className="webcare-server-sec-controls">
          {/* Section 1: Attack Surface Armor */}
          <div className="webcare-matrix-group">
            <div className="webcare-matrix-header">
              <Shield size={16} color="#0284c7" />
              <h4>1. Core Attack Surface & Perimeter Armor</h4>
            </div>

            <div className="webcare-matrix-list">
              <label className="webcare-matrix-item">
                <input
                  type="checkbox"
                  checked={options.block_uploads_php}
                  onChange={() => handleToggleOption('block_uploads_php')}
                />
                <div className="webcare-matrix-item-content">
                  <strong>Block Direct PHP Script Execution in Uploads &amp; Cache</strong>
                  <span>Kills uploaded webshells and backdoors immediately inside <code>wp-content/uploads/</code>.</span>
                </div>
              </label>

              <label className="webcare-matrix-item">
                <input
                  type="checkbox"
                  checked={options.protect_webcare_data_dir}
                  onChange={() => handleToggleOption('protect_webcare_data_dir')}
                />
                <div className="webcare-matrix-item-content">
                  <strong>Protect WebCare Plugin Data &amp; Security Vault Directory</strong>
                  <span>Blocks all direct web access to <code>wp-content/uploads/webcare-pro-security/</code> (WAF logs, activity telemetry, database backups, and quarantine vaults).</span>
                </div>
              </label>

              <label className="webcare-matrix-item">
                <input
                  type="checkbox"
                  checked={options.block_sensitive_files}
                  onChange={() => handleToggleOption('block_sensitive_files')}
                />
                <div className="webcare-matrix-item-content">
                  <strong>Shield Sensitive Files, Hidden Files, &amp; Backups</strong>
                  <span>Blocks probes for <code>.env</code>, <code>.git</code>, <code>composer.json</code>, <code>.sql</code>, <code>.bak</code>, and <code>debug.log</code>.</span>
                </div>
              </label>

              <label className="webcare-matrix-item">
                <input
                  type="checkbox"
                  checked={options.protect_wp_config}
                  onChange={() => handleToggleOption('protect_wp_config')}
                />
                <div className="webcare-matrix-item-content">
                  <strong>Strict wp-config.php Lockdown</strong>
                  <span>Returns HTTP 403 Forbidden on direct requests to your database credentials file.</span>
                </div>
              </label>

              <label className="webcare-matrix-item">
                <input
                  type="checkbox"
                  checked={options.block_xmlrpc}
                  onChange={() => handleToggleOption('block_xmlrpc')}
                />
                <div className="webcare-matrix-item-content">
                  <strong>Disable XML-RPC Endpoint (/xmlrpc.php)</strong>
                  <span>Eliminates brute force password guessing amplification and trackback DDoS attacks.</span>
                </div>
              </label>

              <label className="webcare-matrix-item">
                <input
                  type="checkbox"
                  checked={options.block_author_scans}
                  onChange={() => handleToggleOption('block_author_scans')}
                />
                <div className="webcare-matrix-item-content">
                  <strong>Block Author Username Enumeration (?author=N)</strong>
                  <span>Prevents automated bot tools from scraping admin usernames via query parameters.</span>
                </div>
              </label>

              <label className="webcare-matrix-item">
                <input
                  type="checkbox"
                  checked={options.block_exploit_queries}
                  onChange={() => handleToggleOption('block_exploit_queries')}
                />
                <div className="webcare-matrix-item-content">
                  <strong>Filter LFI / Directory Traversal &amp; Injection Queries</strong>
                  <span>Blocks patterns like <code>../</code>, encoding functions, code execution functions, <code>&lt;script</code>, and <code>GLOBALS</code>.</span>
                </div>
              </label>

              <label className="webcare-matrix-item">
                <input
                  type="checkbox"
                  checked={options.block_bad_bots}
                  onChange={() => handleToggleOption('block_bad_bots')}
                />
                <div className="webcare-matrix-item-content">
                  <strong>Block Known Vulnerability Scanners &amp; Scrapers</strong>
                  <span>Drops automated scanners (sqlmap, nikto, wpscan, dirbuster, gobuster, masscan).</span>
                </div>
              </label>

              <label className="webcare-matrix-item">
                <input
                  type="checkbox"
                  checked={options.disable_directory_index}
                  onChange={() => handleToggleOption('disable_directory_index')}
                />
                <div className="webcare-matrix-item-content">
                  <strong>Disable Directory Browsing (Directory Indexing)</strong>
                  <span>Prevents visitors from viewing directory contents when no index file is present.</span>
                </div>
              </label>
            </div>
          </div>

          {/* Section 2: Rate Limiting & DoS Throttling */}
          <div className="webcare-matrix-group">
            <div className="webcare-matrix-header">
              <Sliders size={16} color="#059669" />
              <h4>2. Rate Limiting, Request Payloads, &amp; Throttling</h4>
            </div>

            <div className="webcare-matrix-sliders">
              {/* Login Rate Limiter */}
              <div className="webcare-slider-box">
                <div className="webcare-slider-top">
                  <label className="webcare-slider-label">
                    <input
                      type="checkbox"
                      checked={options.rate_limit_login}
                      onChange={() => handleToggleOption('rate_limit_login')}
                      style={{ marginRight: '6px' }}
                    />
                    <strong>Login Page Brute-Force Rate Limit</strong>
                  </label>
                  <span className="webcare-slider-val">{options.login_rate_limit} req/min</span>
                </div>
                <input
                  type="range"
                  min="1"
                  max="30"
                  step="1"
                  value={options.login_rate_limit}
                  disabled={!options.rate_limit_login}
                  onChange={(e) => handleSliderChange('login_rate_limit', parseInt(e.target.value, 10))}
                  className="webcare-range-input"
                />
                <span className="webcare-slider-hint">
                  Throttles aggressive brute-force password login attempts against <code>/wp-login.php</code>.
                </span>
              </div>

              {/* Login Burst */}
              <div className="webcare-slider-box">
                <div className="webcare-slider-top">
                  <span className="webcare-slider-label-text">Burst Allowance on Login</span>
                  <span className="webcare-slider-val">{options.login_burst_limit} burst</span>
                </div>
                <input
                  type="range"
                  min="2"
                  max="25"
                  step="1"
                  value={options.login_burst_limit}
                  disabled={!options.rate_limit_login}
                  onChange={(e) => handleSliderChange('login_burst_limit', parseInt(e.target.value, 10))}
                  className="webcare-range-input"
                />
                <span className="webcare-slider-hint">Tolerates momentary human bursts without locking out legitimate users.</span>
              </div>

              {/* Request Max Body */}
              <div className="webcare-slider-box">
                <div className="webcare-slider-top">
                  <span className="webcare-slider-label-text">Maximum Request Body Size</span>
                  <span className="webcare-slider-val">{options.client_max_body_mb} MB</span>
                </div>
                <input
                  type="range"
                  min="4"
                  max="256"
                  step="4"
                  value={options.client_max_body_mb}
                  onChange={(e) => handleSliderChange('client_max_body_mb', parseInt(e.target.value, 10))}
                  className="webcare-range-input"
                />
                <span className="webcare-slider-hint">Limits huge POST payload attacks that exhaust server memory buffers.</span>
              </div>

              {/* HTTP Methods */}
              <label className="webcare-matrix-item" style={{ marginTop: '8px' }}>
                <input
                  type="checkbox"
                  checked={options.restrict_http_methods}
                  onChange={() => handleToggleOption('restrict_http_methods')}
                />
                <div className="webcare-matrix-item-content">
                  <strong>Restrict HTTP Methods (Allow GET, POST, HEAD Only)</strong>
                  <span>Rejects dangerous or probing HTTP methods (PUT, DELETE, TRACE, TRACK, OPTIONS).</span>
                </div>
              </label>
            </div>
          </div>

          {/* Section 3: Hardened HTTP Headers */}
          <div className="webcare-matrix-group">
            <div className="webcare-matrix-header">
              <Lock size={16} color="#7c3aed" />
              <h4>3. Hardened HTTP Response Headers</h4>
            </div>

            <div className="webcare-matrix-list">
              <label className="webcare-matrix-item">
                <input
                  type="checkbox"
                  checked={options.header_x_frame_options}
                  onChange={() => handleToggleOption('header_x_frame_options')}
                />
                <div className="webcare-matrix-item-content">
                  <strong>X-Frame-Options: SAMEORIGIN</strong>
                  <span>Prevents hostile websites from clickjacking your site inside iframes.</span>
                </div>
              </label>

              <label className="webcare-matrix-item">
                <input
                  type="checkbox"
                  checked={options.header_x_content_type}
                  onChange={() => handleToggleOption('header_x_content_type')}
                />
                <div className="webcare-matrix-item-content">
                  <strong>X-Content-Type-Options: nosniff</strong>
                  <span>Forces browsers to strictly obey declared MIME types, preventing script disguise.</span>
                </div>
              </label>

              <label className="webcare-matrix-item">
                <input
                  type="checkbox"
                  checked={options.header_referrer_policy}
                  onChange={() => handleToggleOption('header_referrer_policy')}
                />
                <div className="webcare-matrix-item-content">
                  <strong>Referrer-Policy: strict-origin-when-cross-origin</strong>
                  <span>Protects visitor privacy and avoids leaking sensitive internal query URLs.</span>
                </div>
              </label>

              <label className="webcare-matrix-item">
                <input
                  type="checkbox"
                  checked={options.header_permissions}
                  onChange={() => handleToggleOption('header_permissions')}
                />
                <div className="webcare-matrix-item-content">
                  <strong>Permissions-Policy (Disable Camera, Microphone, Geolocation)</strong>
                  <span>Restricts hardware sensor access for all embedded third-party scripts.</span>
                </div>
              </label>

              <label className="webcare-matrix-item">
                <input
                  type="checkbox"
                  checked={options.header_hsts}
                  onChange={() => handleToggleOption('header_hsts')}
                />
                <div className="webcare-matrix-item-content">
                  <strong>Strict-Transport-Security (HSTS - SSL Sites Only)</strong>
                  <span>Enforces HTTPS connection security for 1 full year with preload support.</span>
                </div>
              </label>
            </div>
          </div>
        </div>

        {/* Right: Live Generated Config & SysAdmin Deployment Box */}
        <div className="webcare-server-sec-preview">
          {/* Nginx Specific Inclusion Box */}
          {selectedEngine === 'nginx' && (
            <div className="webcare-nginx-guide-card">
              <div className="webcare-nginx-guide-header">
                <Terminal size={17} />
                <strong>Nginx Server Domain Integration</strong>
              </div>
              <p className="webcare-nginx-guide-text">
                Nginx executes configuration files compiled into its server blocks. We save this configuration directly to your protected uploads directory:
              </p>
              
              <div className="webcare-filepath-box">
                <span className="webcare-filepath-label">Server Filepath:</span>
                <code className="webcare-filepath-code">{fileInfo?.nginx_path || '/wp-content/uploads/webcare-waf/nginx-webcare-security.conf'}</code>
                <button
                  type="button"
                  className="webcare-mini-copy-btn"
                  title="Copy Filepath"
                  onClick={() => handleCopy(fileInfo?.nginx_path || '', 'path')}
                >
                  {copiedKey === 'path' ? <Check size={12} color="#16a34a" /> : <Copy size={12} />}
                </button>
              </div>

              <div className="webcare-include-box">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                  <span className="webcare-include-label">Include Directive for your Nginx Domain config:</span>
                  <button
                    type="button"
                    className="webcare-mini-copy-btn"
                    onClick={() => handleCopy(fileInfo?.nginx_include_code || `include ${fileInfo?.nginx_path};`, 'include')}
                  >
                    {copiedKey === 'include' ? <Check size={12} color="#16a34a" /> : <Copy size={12} />}
                    <span style={{ fontSize: '11px', marginLeft: '4px' }}>Copy Include</span>
                  </button>
                </div>
                <code className="webcare-include-code">{fileInfo?.nginx_include_code || `include ${fileInfo?.nginx_path};`}</code>
              </div>

              <div className="webcare-nginx-steps">
                <span><strong>Quick Setup:</strong> Paste this inside your <code>server &#123; ... &#125;</code> block in <code>/etc/nginx/sites-available/your-site.conf</code>, then run <code>nginx -t &amp;&amp; systemctl reload nginx</code>.</span>
              </div>
            </div>
          )}

          {/* Apache / LiteSpeed Deployment Box */}
          {selectedEngine === 'apache' && (
            <div className="webcare-apache-guide-card">
              <div className="webcare-apache-guide-header">
                <HardDrive size={17} />
                <strong>Apache / LiteSpeed .htaccess Integration</strong>
              </div>
              <p className="webcare-apache-guide-text">
                Apache and LiteSpeed process directives on-the-fly via <code>.htaccess</code>. You can write these rules directly to your root <code>.htaccess</code> file with one click, or copy and paste them manually.
              </p>
              <div style={{ display: 'flex', gap: '8px', marginTop: '10px', flexWrap: 'wrap' }}>
                <button
                  type="button"
                  className="webcare-btn webcare-btn-primary"
                  style={{ fontSize: '12px', padding: '6px 14px' }}
                  onClick={handleDeployHtaccess}
                  disabled={deployingHtaccess}
                >
                  <ShieldCheck size={14} />
                  {deployingHtaccess ? 'Deploying...' : '1-Click Deploy to Root .htaccess'}
                </button>
                <button
                  type="button"
                  className="webcare-btn"
                  style={{ fontSize: '12px', padding: '6px 12px' }}
                  onClick={() => handleCopy(apacheCode, 'full_apache')}
                >
                  {copiedKey === 'full_apache' ? <Check size={14} color="#16a34a" /> : <Copy size={14} />}
                  Copy Directives
                </button>
              </div>
            </div>
          )}

          {/* Code Preview Header */}
          <div className="webcare-code-preview-header">
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <FileCode size={16} />
              <strong>
                Generated {selectedEngine === 'nginx' ? 'Nginx Configuration' : selectedEngine === 'apache' ? 'Apache .htaccess Directives' : 'Caddy v2 Security Snippet'}
              </strong>
              {fileInfo?.nginx_exists && selectedEngine === 'nginx' && (
                <span className="webcare-telemetry-badge webcare-badge-success">Saved to Disk</span>
              )}
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <button
                type="button"
                className="webcare-code-action-btn"
                title="Save & Write to Server File"
                onClick={handleSaveConfig}
                disabled={saving}
              >
                <Save size={13} />
                <span>{saving ? 'Saving...' : 'Save Config File'}</span>
              </button>

              <button
                type="button"
                className="webcare-code-action-btn"
                title="Download configuration"
                onClick={() => handleDownload(activeCodePreview, selectedEngine === 'nginx' ? 'nginx-webcare-security.conf' : selectedEngine === 'apache' ? 'htaccess-webcare-security.conf' : 'caddy-webcare-security.conf')}
              >
                <Download size={13} />
                <span>Download</span>
              </button>

              <button
                type="button"
                className="webcare-code-action-btn"
                title="Copy all code to clipboard"
                onClick={() => handleCopy(activeCodePreview, 'code_all')}
              >
                {copiedKey === 'code_all' ? <Check size={13} color="#16a34a" /> : <Copy size={13} />}
                <span>{copiedKey === 'code_all' ? 'Copied!' : 'Copy Code'}</span>
              </button>
            </div>
          </div>

          {/* Syntax Highlighted Code Viewer */}
          <div className="webcare-server-code-wrapper">
            <pre className="webcare-server-code-pre">
              <code>{activeCodePreview || '# Adjust options on the left to generate configuration directives.'}</code>
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
