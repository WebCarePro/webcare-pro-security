import React from 'react';
import {
  Radar,
  Target,
  FileCode,
  ShieldAlert,
  History,
  Activity,
  Shield,
  PlayCircle,
  Radio,
  Server,
  Globe,
  Cloud,
  Zap,
  Key,
  Fingerprint,
  Users,
  Lock,
  XCircle,
  Sliders,
  Archive,
  Database,
  RotateCcw,
  Sparkles,
  Clock,
  ShieldCheck,
  Filter,
  HardDrive,
  Calendar,
  MessageSquare,
  Bell,
  Bot,
  Cpu,
  FileText,
  LifeBuoy,
  Layers,
  FileCheck,
  Link,
  GitBranch,
  Laptop,
  Terminal,
} from 'lucide-react';

export type NavigationPillar =
  | 'Scanner & CVEs'
  | 'Firewall & Edge'
  | 'Login & Access'
  | 'Vault & Tools'
  | 'Settings & System';

export interface NavigationItem {
  id: string;
  title: string;
  desc: string;
  icon: React.ElementType;
  pillar: NavigationPillar;
  slug: string;
  tab?: string;
  subtab?: string;
  nestedSubTab?: string;
  badge?: string;
  badgeType?: 'danger' | 'warning' | 'info' | 'success';
  keywords: string[];
  intents?: string[];
  isAdvanced?: boolean;
  isPopular?: boolean;
}

export const NAVIGATION_CATALOG: NavigationItem[] = [
  // ==========================================
  // 1. Scanner & CVEs Pillar
  // ==========================================
  {
    id: 'scan-main',
    title: 'Malware & Vulnerability Scanner',
    desc: 'Full & quick code inspection across 100+ detection engines',
    icon: Radar,
    pillar: 'Scanner & CVEs',
    slug: 'webcare-pro-scan',
    tab: 'scan',
    isPopular: true,
    keywords: ['scan', 'malware', 'virus', 'trojan', 'webshell', 'security scan', 'antivirus', 'core', 'plugins', 'themes', 'detector', 'clean'],
    intents: ['run scan', 'check website for malware', 'scan plugins for backdoor']
  },
  {
    id: 'scan-targeted',
    title: 'Targeted Audits',
    desc: 'Stand-alone focused checks for database, admins, and file vectors',
    icon: Target,
    pillar: 'Scanner & CVEs',
    slug: 'webcare-pro-scan',
    tab: 'targeted',
    isAdvanced: true,
    keywords: ['targeted', 'audit', 'database', 'admin check', 'sensitive files', 'obfuscation', 'custom scan'],
    intents: ['run targeted audit', 'check admin accounts', 'scan database for spam']
  },
  {
    id: 'scan-fim',
    title: 'File Integrity Monitor (FIM)',
    desc: 'Cryptographic SHA-256 diff against official WordPress.org releases',
    icon: FileCode,
    pillar: 'Scanner & CVEs',
    slug: 'webcare-pro-fim',
    tab: 'fim',
    badge: 'SHA-256',
    badgeType: 'info',
    keywords: ['fim', 'integrity', 'checksum', 'core diff', 'tamper', 'file diff', 'hash verification', 'modified files', 'wordpress core'],
    intents: ['check core file changes', 'verify wordpress files against checksums']
  },
  {
    id: 'scan-cve',
    title: 'Vulnerabilities & CVE Intelligence',
    desc: 'Real-time CVE threat intelligence for installed plugins, themes & core',
    icon: ShieldAlert,
    pillar: 'Scanner & CVEs',
    slug: 'webcare-pro-scan',
    tab: 'vulnerabilities',
    badge: 'CVE INTEL',
    badgeType: 'danger',
    isPopular: true,
    keywords: ['cve', 'vulnerability', 'exploit', 'known bugs', 'advisory', 'patch', 'nist', 'nvd', 'security updates', 'cisa kev', 'virtual patch'],
    intents: ['check plugin vulnerabilities', 'review cve alerts', 'unpatched plugins']
  },
  {
    id: 'scan-logs',
    title: 'Scan Logs & Audit History',
    desc: 'Chronological timeline of all historical scan sessions and remediation actions',
    icon: History,
    pillar: 'Scanner & CVEs',
    slug: 'webcare-pro-scan',
    tab: 'logs',
    badge: 'LOGS',
    badgeType: 'info',
    keywords: ['logs', 'history', 'archive', 'reports', 'scan log', 'csv', 'audit trail'],
    intents: ['view previous scan reports', 'download scan history']
  },

  // ==========================================
  // 2. Firewall & Edge Pillar
  // ==========================================
  {
    id: 'fw-stream',
    title: 'Live Traffic & Incident Stream',
    desc: 'Real-time telemetry feed of incoming HTTP requests and blocked threats',
    icon: Activity,
    pillar: 'Firewall & Edge',
    slug: 'webcare-pro-firewall',
    tab: 'stream',
    keywords: ['traffic', 'stream', 'live', 'telemetry', 'real-time', 'packets', 'requests', 'monitor', 'live stream', 'live traffic'],
    intents: ['view real time traffic', 'see incoming attacks live']
  },
  {
    id: 'fw-rules',
    title: 'Rules & Presets',
    desc: 'Layer 7 inspection rules for SQLi, XSS, RCE, upload shields, and bypasses',
    icon: Shield,
    pillar: 'Firewall & Edge',
    slug: 'webcare-pro-firewall',
    tab: 'rules',
    badge: 'WAF',
    badgeType: 'danger',
    isPopular: true,
    keywords: ['firewall', 'waf', 'rules', 'sqli', 'xss', 'rce', 'block', 'traffic', 'filter', 'lfi', 'upload shield', 'whitelist', 'presets', 'allowlist'],
    intents: ['configure firewall rules', 'whitelist ip address', 'turn on sqli protection']
  },
  {
    id: 'fw-caf',
    title: 'Adaptive Firewall (CAF) & StackGuard',
    desc: 'Smart protection profiles and automatic dormant plugin surface lock',
    icon: Sparkles,
    pillar: 'Firewall & Edge',
    slug: 'webcare-pro-firewall',
    tab: 'caf',
    badge: 'StackGuard',
    badgeType: 'info',
    isAdvanced: true,
    keywords: ['caf', 'adaptive', 'stackguard', 'profiles', 'smart protection', 'ecommerce preset', 'membership'],
    intents: ['tune adaptive firewall', 'enable stackguard']
  },
  {
    id: 'fw-cf',
    title: 'Cloudflare Edge Defense',
    desc: 'Direct synchronization with Cloudflare Edge IP Lists and zero-token WAF rules',
    icon: Cloud,
    pillar: 'Firewall & Edge',
    slug: 'webcare-pro-firewall',
    tab: 'cloudflare',
    badge: 'EDGE',
    badgeType: 'warning',
    isPopular: true,
    isAdvanced: true,
    keywords: ['cloudflare', 'edge', 'sync', 'turnstile', 'api', 'cdn', 'firewall rule', 'ip list', 'edge defense'],
    intents: ['sync blocked ips with cloudflare', 'manage cloudflare waf rules']
  },
  {
    id: 'fw-behavioral',
    title: 'Bot & Behavioral WAF',
    desc: 'Machine-speed heuristic profiling, route baselines, and parameter variance tracking',
    icon: Sliders,
    pillar: 'Firewall & Edge',
    slug: 'webcare-pro-firewall',
    tab: 'behavioral',
    isAdvanced: true,
    keywords: ['behavioral waf', 'route profile', 'learning mode', 'adaptive learning', 'benign traffic', 'profiler', 'bot', 'behavior'],
    intents: ['tune bot behavioral rules', 'inspect route learning mode']
  },
  {
    id: 'fw-behavioral-learning',
    title: 'Learning Mode 2.0 & Profiles',
    desc: 'Inspect learned parameter schemas, schema confidence, and auto-graduating routes',
    icon: Target,
    pillar: 'Firewall & Edge',
    slug: 'webcare-pro-firewall',
    tab: 'behavioral',
    nestedSubTab: 'learning',
    isAdvanced: true,
    keywords: ['learning mode', 'route profile', 'adaptive', 'schema observation', 'graduation', 'safe mode'],
    intents: ['view route parameters in learning mode']
  },
  {
    id: 'fw-behavioral-honeytoken',
    title: 'Phantom Bot Traps (Honey-Tokens)',
    desc: 'Zero-overhead invisible decoy traps catching automated credential stuffers',
    icon: Bot,
    pillar: 'Firewall & Edge',
    slug: 'webcare-pro-firewall',
    tab: 'behavioral',
    nestedSubTab: 'honeytoken',
    badge: 'TRAPS',
    badgeType: 'warning',
    isAdvanced: true,
    keywords: ['phantom bot', 'honeytoken', 'form trap', 'honeypot', 'auto ban', 'bot trap', 'blocked'],
    intents: ['configure bot traps', 'set up honeypot form fields']
  },
  {
    id: 'fw-behavioral-ratelimit',
    title: 'Adaptive Rate Limiter & Throttling',
    desc: 'Token-bucket rate limiter applying HTTP 429 graceful backoff before harsh bans',
    icon: Zap,
    pillar: 'Firewall & Edge',
    slug: 'webcare-pro-firewall',
    tab: 'behavioral',
    nestedSubTab: 'ratelimit',
    isAdvanced: true,
    keywords: ['rate limit', 'throttling', 'token bucket', 'http 429', 'anti abuse', 'burst control'],
    intents: ['limit request rates', 'prevent brute-force flood']
  },
  {
    id: 'fw-ai-defense',
    title: '2026 AI Defense & Decoy Traps',
    desc: 'Autonomous prompt injection defense, LLM honeypots, and AI scraping decoys',
    icon: Bot,
    pillar: 'Firewall & Edge',
    slug: 'webcare-pro-firewall',
    tab: 'ai_defense',
    badge: '2026 AI',
    badgeType: 'info',
    isAdvanced: true,
    keywords: ['ai defense', 'prompt injection', 'decoy', 'llm bot', 'chatgpt bot', 'ai scraping', 'honeypot', 'mcp'],
    intents: ['block ai scrapers', 'prevent prompt injection']
  },
  {
    id: 'fw-ai-ghost',
    title: 'Ghost Routes & Canary Bot Traps',
    desc: 'Synthetic API endpoints trapping scraping bots and aggressive crawlers',
    icon: Radio,
    pillar: 'Firewall & Edge',
    slug: 'webcare-pro-firewall',
    tab: 'ai_defense',
    nestedSubTab: 'ghost',
    isAdvanced: true,
    keywords: ['ghost routes', 'canary bot', 'synthetic endpoints', 'bot trap', 'decoy routes'],
    intents: ['enable ghost routes']
  },
  {
    id: 'fw-ai-egress',
    title: 'Outbound AI & SSRF Egress Shield',
    desc: 'Deep egress firewall preventing prompt data exfiltration and internal host scanning',
    icon: Globe,
    pillar: 'Firewall & Edge',
    slug: 'webcare-pro-firewall',
    tab: 'ai_defense',
    nestedSubTab: 'egress',
    isAdvanced: true,
    keywords: ['egress', 'ssrf', 'outbound firewall', 'ai exfiltration', 'network egress'],
    intents: ['block ssrf and internal ip scanning']
  },
  {
    id: 'fw-ai-prompt',
    title: 'Prompt Injection Guard',
    desc: 'Real-time inspection neutralizing jailbreaks, delimiter hijacking, and prompt attacks',
    icon: Sparkles,
    pillar: 'Firewall & Edge',
    slug: 'webcare-pro-firewall',
    tab: 'ai_defense',
    nestedSubTab: 'prompt',
    isAdvanced: true,
    keywords: ['prompt injection', 'jailbreak', 'llm defense', 'prompt guard', 'delimiter hijacking'],
    intents: ['neutralize prompt injections']
  },
  {
    id: 'fw-ai-credentials',
    title: 'API Key & Credential Scanner',
    desc: 'Continuous scanning for exposed OpenAI, Anthropic, Gemini, and database secret keys',
    icon: Key,
    pillar: 'Firewall & Edge',
    slug: 'webcare-pro-firewall',
    tab: 'ai_defense',
    nestedSubTab: 'credentials',
    isAdvanced: true,
    keywords: ['api key scanner', 'credential leak', 'secret scanner', 'openai key', 'gemini key'],
    intents: ['scan for exposed api keys']
  },
  {
    id: 'fw-ai-surface',
    title: 'REST API & AJAX Attack Surface',
    desc: 'Interactive surface explorer cataloging all registered endpoints, authentication, and risks',
    icon: Server,
    pillar: 'Firewall & Edge',
    slug: 'webcare-pro-firewall',
    tab: 'ai_defense',
    nestedSubTab: 'surface',
    isAdvanced: true,
    keywords: ['attack surface', 'rest api', 'ajax actions', 'route audit', 'endpoint security'],
    intents: ['view rest api attack surface']
  },
  {
    id: 'fw-drill',
    title: 'Red Team Attack Drill',
    desc: 'Simulate live attack vectors to stress test firewall defensibility & alerts',
    icon: PlayCircle,
    pillar: 'Firewall & Edge',
    slug: 'webcare-pro-firewall',
    tab: 'drill',
    badge: 'RED TEAM',
    badgeType: 'warning',
    isAdvanced: true,
    keywords: ['attack drill', 'red team', 'simulation', 'stress test', 'exploit test', 'waf verification'],
    intents: ['run red team attack drill', 'verify waf detection']
  },
  {
    id: 'fw-supply-chain',
    title: 'Supply-Chain Defense & SBOM Hub',
    desc: 'Master supply chain hub protecting runtime anchors, drop-ins, and dependencies',
    icon: Layers,
    pillar: 'Firewall & Edge',
    slug: 'webcare-pro-firewall',
    tab: 'supply_chain',
    badge: 'SBOM',
    badgeType: 'info',
    isAdvanced: true,
    keywords: ['supply chain', 'sbom', 'drop-in', 'mu-plugin', 'lockfile', 'gatekeeper', 'dependency'],
    intents: ['inspect software bill of materials', 'check supply chain security']
  },
  {
    id: 'fw-sbom-ledger',
    title: 'Drop-ins & SBOM Ledger',
    desc: 'Cryptographic inventory of active drop-ins, mu-plugins, and runtime anchors',
    icon: FileCheck,
    pillar: 'Firewall & Edge',
    slug: 'webcare-pro-firewall',
    tab: 'supply_chain',
    nestedSubTab: 'sbom',
    isAdvanced: true,
    keywords: ['drop-in', 'mu-plugin', 'sbom ledger', 'object-cache', 'db.php', 'advanced-cache', 'baseline hash', 'sbom'],
    intents: ['view drop-in file hashes']
  },
  {
    id: 'fw-gatekeeper',
    title: 'Update Gatekeeper Audits',
    desc: 'Pre-install plugin update sandbox inspecting diffs and hostile code mutations',
    icon: ShieldAlert,
    pillar: 'Firewall & Edge',
    slug: 'webcare-pro-firewall',
    tab: 'supply_chain',
    nestedSubTab: 'gatekeeper',
    isAdvanced: true,
    keywords: ['update gatekeeper', 'sandbox', 'pre-install', 'diff', 'update inspection', 'rollback'],
    intents: ['inspect updates before installing']
  },
  {
    id: 'fw-advisor',
    title: 'Shift-Left Risk Analyzer',
    desc: 'Predictive risk scoring for new plugins before downloading from WordPress.org',
    icon: Sparkles,
    pillar: 'Firewall & Edge',
    slug: 'webcare-pro-firewall',
    tab: 'supply_chain',
    nestedSubTab: 'advisor',
    isAdvanced: true,
    keywords: ['risk analyzer', 'shift left', 'plugin safety', 'trust score', 'reputation', 'abandoned'],
    intents: ['score plugin safety']
  },
  {
    id: 'fw-lockfiles',
    title: 'Dependency Lockfiles',
    desc: 'Inspect composer.lock, package-lock.json, and PHP vendor library integrity',
    icon: GitBranch,
    pillar: 'Firewall & Edge',
    slug: 'webcare-pro-firewall',
    tab: 'supply_chain',
    nestedSubTab: 'lockfiles',
    isAdvanced: true,
    keywords: ['composer.lock', 'package-lock.json', 'vendor', 'dependencies', 'cve lockfile', 'npm'],
    intents: ['audit vendor lockfiles']
  },
  {
    id: 'fw-scripts',
    title: 'Client JS & Hostname Drift',
    desc: 'Monitor enqueued frontend scripts, remote CDN origins, and client-side drift',
    icon: Link,
    pillar: 'Firewall & Edge',
    slug: 'webcare-pro-firewall',
    tab: 'supply_chain',
    nestedSubTab: 'scripts',
    isAdvanced: true,
    keywords: ['client js', 'hostname drift', 'script inventory', 'cdn', 'magecart', 'skimmer', 'checkout'],
    intents: ['detect client side magecart skimmers']
  },
  {
    id: 'fw-server-sec',
    title: 'Server Security (Nginx / Apache)',
    desc: 'Web server hardening rules, .htaccess/.user.ini guards, and directory protection',
    icon: Server,
    pillar: 'Firewall & Edge',
    slug: 'webcare-pro-firewall',
    tab: 'server_sec',
    isAdvanced: true,
    keywords: ['server security', 'nginx', 'apache', 'htaccess', 'user.ini', 'upload protection', 'web server', 'headers'],
    intents: ['harden web server configs']
  },
  {
    id: 'fw-intel',
    title: 'Cloud Threat Intel & Botnets',
    desc: 'Curated malicious botnet IP feeds, reputation lists, and canary telemetry',
    icon: Globe,
    pillar: 'Firewall & Edge',
    slug: 'webcare-pro-firewall',
    tab: 'intel',
    isAdvanced: true,
    keywords: ['threat intel', 'blacklist', 'botnet', 'honeypot', 'bad ips', 'feed', 'reputation', 'blocked'],
    intents: ['view cloud threat intelligence feeds']
  },
  {
    id: 'fw-vpatch',
    title: 'Virtual Patching & 0-Day Shield',
    desc: '1-click virtual patching for 0-day vulnerabilities before official updates release',
    icon: Zap,
    pillar: 'Firewall & Edge',
    slug: 'webcare-pro-firewall',
    tab: 'vpatch',
    badge: '0-DAY',
    badgeType: 'warning',
    isPopular: true,
    isAdvanced: true,
    keywords: ['vpatch', 'virtual patch', 'zero day', '0day', 'exploit shield', 'studio', 'hotfix'],
    intents: ['activate zero day virtual patches']
  },
  {
    id: 'fw-logs',
    title: 'WAF Incident Logs & Forensics',
    desc: 'Searchable forensic ledger of all intercepted malicious payloads and requests',
    icon: History,
    pillar: 'Firewall & Edge',
    slug: 'webcare-pro-waf-logs',
    badge: 'LOGS',
    badgeType: 'info',
    isPopular: true,
    keywords: ['waf logs', 'blocked', 'incident', 'attack log', 'forensic', 'fail2ban', '403', 'unban', 'whitelist', 'visitor blocked', 'unban ip'],
    intents: ['unban ip address', 'unblock customer', 'inspect blocked visitor request']
  },
  {
    id: 'fw-bans-allowlists',
    title: 'Bans, Block & Allowlist Rules',
    desc: 'Banned IPs, trusted whitelists, URL exemptions, progressive enforcement & targeted bypasses',
    icon: Ban,
    pillar: 'Firewall & Edge',
    slug: 'webcare-pro-waf-logs',
    tab: 'rules',
    badge: 'BANS & ALLOWLIST',
    badgeType: 'danger',
    isPopular: true,
    keywords: ['bans', 'blocked', 'blocked ip', 'whitelist', 'allowlist', 'unban', 'allowlisted urls', 'progressive enforcement', 'soft block', 'bypass rules', 'visitor blocked', 'unban ip', 'safe ip'],
    intents: ['manage blocked ip addresses', 'unban visitor', 'add whitelisted ip', 'allowlist url endpoint']
  },
  {
    id: 'fw-modular-waf',
    title: 'Modular Firewall Rules & AST Studio',
    desc: 'Autonomous site-tailored modular rules synthesized from PHP AST & endpoint profiles',
    icon: Radar,
    pillar: 'Firewall & Edge',
    slug: 'webcare-pro-modular-waf',
    tab: 'rules',
    badge: 'AST WAF',
    badgeType: 'success',
    isAdvanced: true,
    keywords: ['modular waf', 'ast', 'synthesizer', 'guest ajax', 'permissive rest', 'direct script', 'cve shield', 'export json', 'autopilot'],
    intents: ['open modular firewall studio']
  },
  {
    id: 'fw-modular-dossier',
    title: 'Component Behavioral Dossier',
    desc: 'Deep component inventory, WordPress.org checksum forensics & taint endpoint tracebacks',
    icon: Layers,
    pillar: 'Firewall & Edge',
    slug: 'webcare-pro-modular-waf',
    tab: 'dossier',
    badge: 'AST TRACE',
    badgeType: 'info',
    isAdvanced: true,
    keywords: ['behavioral dossier', 'component inventory', 'checksum forensics', 'plugin trace', 'theme trace', 'taint'],
    intents: ['inspect component behavioral dossier']
  },
  {
    id: 'fw-visual-rule-studio',
    title: 'Custom Firewall Rules & AI Builder',
    desc: 'Build custom block/allow rules across 18 request fields with 1-click AI generation',
    icon: Filter,
    pillar: 'Firewall & Edge',
    slug: 'webcare-pro-modular-waf',
    tab: 'builder',
    badge: 'Custom Rules',
    badgeType: 'info',
    isAdvanced: true,
    keywords: ['custom firewall rules', 'custom rules', 'ai firewall', 'wirefilter', 'cloudflare edge', 'simulate', 'pow challenge', 'custom rule', 'visual rule builder'],
    intents: ['create custom firewall rule', 'use wirefilter rule builder']
  },
  {
    id: 'fw-nextgen-ecosystem',
    title: 'Pluggable Module SDK & Next-Gen Sentinels',
    desc: 'AI Kill-Chain Detector, Guest SQL RASP, Upgrader Delta AST, Checkout Skimmer CSP',
    icon: Cpu,
    pillar: 'Firewall & Edge',
    slug: 'webcare-pro-modular-waf',
    tab: 'nextgen',
    badge: '6 Engines',
    badgeType: 'success',
    isAdvanced: true,
    keywords: ['module sdk', 'next-gen', 'sql rasp', 'intent chain', 'graphql', 'checkout skimmer', 'dlp', 'delta', 'checkout'],
    intents: ['configure next-gen sentinel engines']
  },
  {
    id: 'safe_mode',
    title: '15-Minute Safe Mode (Pause Firewall)',
    desc: 'Temporarily relax firewall rules to diagnose checkout or plugin conflicts.',
    icon: WrenchIconPlaceholder,
    pillar: 'Firewall & Edge',
    slug: 'webcare-pro-security&rescue=1',
    isPopular: true,
    keywords: ['safe mode', 'pause firewall', 'checkout broken', 'disable waf', 'troubleshoot', 'emergency pause', 'rescue', 'checkout'],
    intents: ['pause firewall for 15 minutes', 'fix broken checkout with safe mode']
  },

  // ==========================================
  // 3. Login & 2FA Pillar
  // ==========================================
  {
    id: 'id-2fa',
    title: 'Two-Factor Auth (2FA)',
    desc: 'RFC 6238 TOTP authenticator app enforcement and emergency backup codes',
    icon: Key,
    pillar: 'Login & Access',
    slug: 'webcare-pro-auth',
    tab: '2fa',
    badge: '2FA',
    badgeType: 'success',
    isPopular: true,
    keywords: ['2fa', 'totp', 'mfa', 'two factor', 'authenticator', 'google authenticator', 'authy', 'login', 'passkey'],
    intents: ['set up two-factor authentication', 'generate 2fa backup codes']
  },
  {
    id: 'id-passkeys',
    title: 'WebAuthn Passkeys & Biometrics',
    desc: 'FIDO2 hardware keys, Touch ID, Face ID, and biometric device credential management',
    icon: Fingerprint,
    pillar: 'Login & Access',
    slug: 'webcare-pro-auth',
    tab: 'passkeys',
    badge: 'FIDO2',
    badgeType: 'success',
    isPopular: true,
    keywords: ['passkey', 'webauthn', 'fido2', 'biometric', 'touch id', 'face id', 'yubikey', 'hardware key', '2fa'],
    intents: ['register hardware passkey', 'login with touch id']
  },
  {
    id: 'id-admins',
    title: 'Administrator 2FA Enforcement Policy',
    desc: 'Mandatory two-factor authentication enforcement policy for privileged administrator accounts',
    icon: Users,
    pillar: 'Login & Access',
    slug: 'webcare-pro-auth',
    tab: 'admins',
    keywords: ['2fa', 'admin', 'policy', 'enforcement', 'mfa', 'user audit', 'require 2fa'],
    intents: ['enforce 2fa for all administrators']
  },
  {
    id: 'id-travel',
    title: 'Session Forensics & Impossible Travel',
    desc: 'Concurrent active user sessions and impossible velocity geo-travel anomaly alarms',
    icon: Activity,
    pillar: 'Login & Access',
    slug: 'webcare-pro-auth',
    tab: 'zero_trust',
    subtab: 'sessions',
    isAdvanced: true,
    keywords: ['session', 'forensics', 'travel', 'geo', 'concurrent', 'login session', 'ip directory', 'velocity'],
    intents: ['inspect active user sessions', 'view impossible travel alerts']
  },
  {
    id: 'id-hibp',
    title: 'Credential Leak Armor & HIBP',
    desc: 'Real-time HaveIBeenPwned API check and compromised password rejection armor',
    icon: Key,
    pillar: 'Login & Access',
    slug: 'webcare-pro-auth',
    tab: 'zero_trust',
    subtab: 'breach',
    badge: 'HIBP',
    badgeType: 'danger',
    keywords: ['hibp', 'haveibeenpwned', 'password', 'compromised', 'leaked', 'breached', 'credential leak'],
    intents: ['check compromised passwords', 'reject pwned passwords']
  },
  {
    id: 'id-sessions-sentinel',
    title: 'Active Sessions Sentinel',
    desc: 'Real-time cookie replay and concurrent administrator session guard',
    icon: Laptop,
    pillar: 'Login & Access',
    slug: 'webcare-pro-auth',
    tab: 'sessions',
    isAdvanced: true,
    keywords: ['active sessions', 'sentinel', 'cookie hijack', 'session guard', 'remote logout'],
    intents: ['terminate suspicious active sessions']
  },
  {
    id: 'id-lockouts',
    title: 'Brute-Force & XML-RPC Lockout',
    desc: 'Progressive IP blocking on repeated authentication failures and password spraying',
    icon: XCircle,
    pillar: 'Login & Access',
    slug: 'webcare-pro-auth',
    tab: 'lockouts',
    keywords: ['lockout', 'brute force', 'xml-rpc', 'failed login', 'login protection', 'rate limit', 'blocked'],
    intents: ['configure login lockout thresholds']
  },
  {
    id: 'id-app-passwords',
    title: 'Application Password Sentinel',
    desc: 'Audit and restrict REST API application passwords across user roles.',
    icon: Lock,
    pillar: 'Login & Access',
    slug: 'webcare-pro-auth',
    tab: 'app_passwords',
    isAdvanced: true,
    keywords: ['application passwords', 'rest auth', 'app pass', 'api keys'],
    intents: ['audit application passwords']
  },
  {
    id: 'id-settings',
    title: 'Identity & Access Policies',
    desc: 'Global login security policies, session lifetime controls, and password rules',
    icon: Sliders,
    pillar: 'Login & Access',
    slug: 'webcare-pro-auth',
    tab: 'settings',
    keywords: ['identity settings', 'session timeout', 'password policy', 'login rules', 'auth config'],
    intents: ['configure login session timeouts']
  },

  // ==========================================
  // 4. Vault & Forensics Pillar
  // ==========================================
  {
    id: 'vault-quarantine',
    title: 'Quarantine Vault',
    desc: 'Securely isolated malicious files with 1-click restore or clean purge',
    icon: Archive,
    pillar: 'Vault & Tools',
    slug: 'webcare-pro-vault',
    tab: 'quarantine',
    keywords: ['quarantine', 'vault', 'isolate', 'malware', 'restore', 'purge', 'neutralize', 'undo quarantine'],
    intents: ['restore quarantined file', 'purge quarantine']
  },
  {
    id: 'vault-db',
    title: 'Database Backup Vault',
    desc: 'Encrypted full SQL snapshots with 1-click recovery before repairs',
    icon: Database,
    pillar: 'Vault & Tools',
    slug: 'webcare-pro-vault',
    tab: 'database',
    badge: 'SQL BACKUP',
    badgeType: 'success',
    isPopular: true,
    keywords: ['backup', 'database', 'sql', 'dump', 'snapshot', 'recovery', 'table backup', 'export db'],
    intents: ['backup database', 'create sql snapshot', 'restore database']
  },
  {
    id: 'vault-rollback',
    title: 'Safety Rollback Ledger',
    desc: 'Audit trail of all file repairs with pre-patch diff restoration',
    icon: RotateCcw,
    pillar: 'Vault & Tools',
    slug: 'webcare-pro-vault',
    tab: 'rollback',
    keywords: ['rollback', 'undo', 'restore', 'repair history', 'revert'],
    intents: ['revert file repair', 'view rollback ledger']
  },
  {
    id: 'vault-secrets',
    title: 'Secrets Vault & Key Rotator',
    desc: 'AES-256 encrypted credential vault with automated cryptographic salt rotation',
    icon: Key,
    pillar: 'Vault & Tools',
    slug: 'webcare-pro-vault',
    tab: 'secrets',
    badge: 'ENCRYPTED',
    badgeType: 'success',
    isAdvanced: true,
    keywords: ['secrets', 'vault', 'encryption', 'key rotation', 'aes-256', 'salt rotator', 'api keys'],
    intents: ['rotate wordpress salts', 'manage secrets vault']
  },
  {
    id: 'for-persistence',
    title: 'Persistence Sentinel',
    desc: 'Scans for stealth cron jobs, disguised mu-plugins, and rogue user hooks',
    icon: Sparkles,
    pillar: 'Vault & Tools',
    slug: 'webcare-pro-forensics',
    tab: 'persistence',
    isAdvanced: true,
    keywords: ['persistence', 'cron', 'mu-plugin', 'stealth', 'backdoor', 'hook', 'cronjob'],
    intents: ['scan for stealth persistence backdoors']
  },
  {
    id: 'for-watchdog',
    title: '72-Hour Reinfection Watchdog',
    desc: 'Automated guardian monitoring cleaned paths for malware resurrection',
    icon: Clock,
    pillar: 'Vault & Tools',
    slug: 'webcare-pro-forensics',
    tab: 'watchdog',
    nestedSubTab: 'watchdog',
    badge: 'WATCHDOG',
    badgeType: 'warning',
    isAdvanced: true,
    keywords: ['reinfection', 'watchdog', 'resurrection', '72 hour', 'persistence', 'clean path'],
    intents: ['monitor reinfection watchdog']
  },
  {
    id: 'for-snapshots',
    title: 'Time-Machine Snapshots',
    desc: 'Local differential snapshots to compare and restore themes and plugins against previous state',
    icon: HardDrive,
    pillar: 'Vault & Tools',
    slug: 'webcare-pro-forensics',
    tab: 'watchdog',
    nestedSubTab: 'snapshots',
    isAdvanced: true,
    keywords: ['snapshots', 'time machine', 'differential', 'restore snapshot', 'theme backup', 'diff', 'backup'],
    intents: ['compare against time-machine snapshot']
  },
  {
    id: 'for-preloaders',
    title: 'Server Pre-Loaders & System Crons',
    desc: 'Monitors auto_prepend_file, server crons, and low-level PHP bootstrap injection vectors',
    icon: Terminal,
    pillar: 'Vault & Tools',
    slug: 'webcare-pro-forensics',
    tab: 'watchdog',
    nestedSubTab: 'preloaders',
    isAdvanced: true,
    keywords: ['preloaders', 'auto_prepend_file', 'server cron', 'system crons', 'bootstrap injection', 'cron'],
    intents: ['check auto_prepend_file injectors']
  },
  {
    id: 'for-reputation',
    title: 'Domain Reputation & SSL Monitor',
    desc: 'Inspects external DNS blacklists, SSL certificate expiry, and domain safety status',
    icon: Globe,
    pillar: 'Vault & Tools',
    slug: 'webcare-pro-forensics',
    tab: 'watchdog',
    nestedSubTab: 'reputation',
    keywords: ['domain reputation', 'ssl monitor', 'dns blacklist', 'certificate expiry', 'ssl check'],
    intents: ['check domain reputation and ssl certificate']
  },
  {
    id: 'for-baseline',
    title: 'Behavioral Baseline Anomaly',
    desc: 'Tracks unusual database schema modifications and unexpected core mutations',
    icon: ShieldCheck,
    pillar: 'Vault & Tools',
    slug: 'webcare-pro-forensics',
    tab: 'baseline',
    isAdvanced: true,
    keywords: ['baseline', 'behavioral', 'anomaly', 'schema mutation', 'tamper', 'core files'],
    intents: ['audit database schema modifications']
  },
  {
    id: 'for-files',
    title: 'Audited Files Forensic Ledger',
    desc: 'Deep inspection catalog of scanned files, hashes, and integrity status',
    icon: FileCode,
    pillar: 'Vault & Tools',
    slug: 'webcare-pro-forensics',
    tab: 'files',
    isAdvanced: true,
    keywords: ['audited files', 'file ledger', 'hash catalog', 'file inspection', 'file list'],
    intents: ['view audited files ledger']
  },
  {
    id: 'for-chain',
    title: 'Attack Chain Reconstruction',
    desc: 'Visual timeline correlating initial infection, payload, and lateral spread',
    icon: Layers,
    pillar: 'Vault & Tools',
    slug: 'webcare-pro-forensics',
    tab: 'attack_chain',
    isAdvanced: true,
    keywords: ['attack chain', 'timeline', 'correlation', 'infection vector', 'lateral', 'killchain'],
    intents: ['reconstruct attack kill chain']
  },
  {
    id: 'for-correlation',
    title: 'Threat Correlation Hierarchy',
    desc: 'Correlate disparate low-severity findings into cohesive multi-stage threat campaigns',
    icon: Target,
    pillar: 'Vault & Tools',
    slug: 'webcare-pro-forensics',
    tab: 'correlation',
    isAdvanced: true,
    keywords: ['correlation', 'threat hierarchy', 'multi-stage', 'campaign', 'clustering'],
    intents: ['view threat correlation hierarchy']
  },
  {
    id: 'for-whitelist',
    title: 'System Whitelist Manager',
    desc: 'Configure verified false positives and customer-whitelisted files',
    icon: Filter,
    pillar: 'Vault & Tools',
    slug: 'webcare-pro-forensics',
    tab: 'whitelist',
    keywords: ['whitelist', 'ignore', 'false positive', 'allowlist', 'approved'],
    intents: ['whitelist false positive file']
  },
  {
    id: 'for-transactions',
    title: 'Remediation Transactions',
    desc: 'Atomic undo ledger recording every automatic remediation and quarantine action',
    icon: History,
    pillar: 'Vault & Tools',
    slug: 'webcare-pro-forensics',
    tab: 'transactions',
    isAdvanced: true,
    keywords: ['remediation', 'transactions', 'atomic undo', 'audit ledger', 'repair log'],
    intents: ['audit remediation transactions']
  },
  {
    id: 'for-self-defense',
    title: 'Plugin Self-Defense Armor',
    desc: 'Cryptographic tamper checks guarding WebCare Pro code and integrity from malware',
    icon: Shield,
    pillar: 'Vault & Tools',
    slug: 'webcare-pro-forensics',
    tab: 'self_defense',
    badge: 'SELF-DEFENSE',
    badgeType: 'info',
    keywords: ['self defense', 'plugin defense', 'tamper check', 'manifest integrity', 'anti-tamper'],
    intents: ['verify plugin self defense status']
  },
  {
    id: 'for-server',
    title: 'Server & PHP Telemetry',
    desc: 'Deep host diagnostic inspecting OPcache, SAPI, limits, and file permissions',
    icon: HardDrive,
    pillar: 'Vault & Tools',
    slug: 'webcare-pro-vault',
    tab: 'server',
    keywords: ['server', 'telemetry', 'php', 'sapi', 'opcache', 'memory', 'disk', 'host', 'environment'],
    intents: ['check php memory limit and opcache']
  },

  // ==========================================
  // 5. Settings & System Pillar
  // ==========================================
  {
    id: 'gov-lockdown',
    title: '1-Click Incident Containment & Panic',
    desc: 'Emergency panic protocol freezing outgoing egress and admin logins',
    icon: ShieldAlert,
    pillar: 'Settings & System',
    slug: 'webcare-pro-settings',
    tab: 'containment',
    badge: 'LOCKDOWN',
    badgeType: 'danger',
    isPopular: true,
    keywords: ['emergency', 'containment', 'lockdown', 'panic', 'incident response', 'freeze', 'panic button'],
    intents: ['activate emergency containment', 'panic lockdown website']
  },
  {
    id: 'gov-schedule',
    title: 'Scan Scheduling & Automation',
    desc: 'Configure hourly, daily, or weekly background cron scans and scope',
    icon: Calendar,
    pillar: 'Settings & System',
    slug: 'webcare-pro-settings',
    tab: 'schedule',
    keywords: ['schedule', 'cron', 'automated', 'timer', 'daily scan', 'weekly scan', 'general'],
    intents: ['schedule daily scans', 'configure automated scanning']
  },
  {
    id: 'gov-email',
    title: 'Email Alert Dispatcher',
    desc: 'Direct SMTP security alert dispatch with priority thresholds and digest reports',
    icon: MessageSquare,
    pillar: 'Settings & System',
    slug: 'webcare-pro-settings',
    tab: 'email',
    keywords: ['email', 'alert', 'smtp', 'digest', 'notification', 'security email'],
    intents: ['configure email security alerts']
  },
  {
    id: 'gov-alerts',
    title: 'DevSecOps Webhooks & Alerts',
    desc: 'Instant notifications to Slack, Discord, Telegram, or custom webhooks',
    icon: Bell,
    pillar: 'Settings & System',
    slug: 'webcare-pro-settings',
    tab: 'webhooks',
    keywords: ['webhooks', 'slack', 'discord', 'telegram', 'email', 'alerts', 'notifications', 'notify'],
    intents: ['send security alerts to slack or discord']
  },
  {
    id: 'gov-cloudflare',
    title: 'Cloudflare Edge API Settings',
    desc: 'Configure Cloudflare Zone ID, API token, and Edge list synchronization keys',
    icon: Cloud,
    pillar: 'Settings & System',
    slug: 'webcare-pro-settings',
    tab: 'cloudflare',
    badge: 'CLOUDFLARE',
    badgeType: 'warning',
    keywords: ['cloudflare api', 'edge sync settings', 'api token', 'zone id', 'cloudflare config'],
    intents: ['enter cloudflare api token']
  },
  {
    id: 'gov-headers',
    title: 'Security Headers Studio',
    desc: 'One-click injection of Content-Security-Policy, HSTS, and X-Frame-Options',
    icon: ShieldCheck,
    pillar: 'Settings & System',
    slug: 'webcare-pro-settings',
    tab: 'headers',
    badge: 'HEADERS',
    badgeType: 'info',
    keywords: ['headers', 'csp', 'hsts', 'x-frame-options', 'cors', 'security headers', 'htaccess'],
    intents: ['enable hsts and csp headers']
  },
  {
    id: 'gov-ai',
    title: 'AI Security Copilot',
    desc: 'Multi-provider AI assistant for automated code explanation and triage',
    icon: Sparkles,
    pillar: 'Settings & System',
    slug: 'webcare-pro-settings',
    tab: 'ai',
    badge: 'AI COPILOT',
    badgeType: 'info',
    keywords: ['ai', 'copilot', 'openai', 'gemini', 'anthropic', 'assistant', 'prompt guard', 'llm', 'mcp'],
    intents: ['configure openai or gemini api keys']
  },
  {
    id: 'gov-mcp',
    title: 'Autonomous MCP Server',
    desc: 'Model Context Protocol endpoint for external AI agent integration',
    icon: Bot,
    pillar: 'Settings & System',
    slug: 'webcare-pro-settings',
    tab: 'mcp',
    badge: 'MCP',
    badgeType: 'info',
    isAdvanced: true,
    keywords: ['mcp', 'model context protocol', 'agent', 'claude code', 'cursor', 'autonomous'],
    intents: ['configure mcp server token']
  },
  {
    id: 'gov-performance',
    title: 'Scanner Engine Tuning',
    desc: 'Chunk size, memory ceiling, thread parallelism, and scan speed tuning',
    icon: Cpu,
    pillar: 'Settings & System',
    slug: 'webcare-pro-settings',
    tab: 'performance',
    isAdvanced: true,
    keywords: ['performance', 'engine tuning', 'chunk size', 'memory limit', 'threads', 'low resource', 'speed', 'timeout'],
    intents: ['speed up malware scan', 'increase memory limit for scan']
  },
  {
    id: 'gov-exclusions',
    title: 'Excluded Paths & Developer Safeguards',
    desc: 'Exclude custom directories, upload folders, cache paths, or file patterns from scans',
    icon: Filter,
    pillar: 'Settings & System',
    slug: 'webcare-pro-settings',
    tab: 'performance',
    badge: 'SAFEGUARDS',
    badgeType: 'info',
    keywords: ['exclude', 'exclusions', 'ignore path', 'ignore folder', 'skip folder', 'skip file', 'ignore pattern', 'cache', 'node_modules', 'whitelist path', 'omit'],
    intents: ['exclude folder from scan', 'ignore cache directory']
  },
  {
    id: 'gov-export',
    title: 'Backup & Policy Migration',
    desc: 'Export and import scanner configurations, custom rules, and white-lists across sites',
    icon: FileText,
    pillar: 'Settings & System',
    slug: 'webcare-pro-settings',
    tab: 'import_export',
    keywords: ['import', 'export', 'migration', 'backup policy', 'configuration json'],
    intents: ['export security configuration', 'import settings json']
  },
  {
    id: 'gov-cleanup',
    title: 'System Purge & Maintenance',
    desc: 'Clear legacy scan caches, flush transient tables, and purge historical telemetry',
    icon: Archive,
    pillar: 'Settings & System',
    slug: 'webcare-pro-settings',
    tab: 'cleanup',
    isAdvanced: true,
    keywords: ['cleanup', 'purge', 'maintenance', 'clear logs', 'flush cache', 'transients'],
    intents: ['purge old scan cache', 'clean database transients']
  },
  {
    id: 'gov-notifications-center',
    title: 'Notification Center',
    desc: 'Consolidated security alert ledger, audit dispatches, and trigger history (60+ Events)',
    icon: Bell,
    pillar: 'Settings & System',
    slug: 'webcare-pro-notifications',
    badge: '60+ EVENTS',
    badgeType: 'info',
    keywords: ['notification center', 'notifications', 'alert ledger', 'broadcast', 'security alerts', 'email alerts', 'webhook matrix', 'slack', 'discord'],
    intents: ['view recent notification dispatches']
  },
  {
    id: 'gov-activity-logs',
    title: 'Plugin Activity & Audit Logs',
    desc: 'Tamper-evident, cryptographically chained AES-256-GCM forensic audit ledger & activity stream',
    icon: Activity,
    pillar: 'Settings & System',
    slug: 'webcare-pro-activity-logs',
    badge: 'AES-256',
    badgeType: 'success',
    isPopular: true,
    keywords: ['plugin activity', 'audit logs', 'activity logs', 'audit ledger', 'forensic trail', 'tamper evident', 'sha-256 chain', 'immutability', 'event history', 'admin actions'],
    intents: ['who changed firewall settings', 'view administrator action audit log']
  },
  {
    id: 'gov-cron-manager',
    title: 'Cron & Task Scheduler Control Center',
    desc: 'Centralized toggle, recurrence, manual trigger, and execution logs for all 15 plugin crons',
    icon: Clock,
    pillar: 'Settings & System',
    slug: 'webcare-pro-cron-manager',
    badge: '15 TASKS',
    badgeType: 'info',
    isAdvanced: true,
    keywords: ['cron', 'schedule', 'task', 'wp-cron', 'scheduler', 'timer', 'automation', 'cron logs', 'background worker'],
    intents: ['manage plugin crons', 'run scheduled task manually']
  },
  {
    id: 'gov-support',
    title: 'About & 1-on-1 Support',
    desc: 'Direct consultation and engineering assistance with Mir Alamin (WebCare Pro)',
    icon: LifeBuoy,
    pillar: 'Settings & System',
    slug: 'webcare-pro-settings',
    tab: 'about',
    keywords: ['about', 'support', 'mir alamin', 'webcare pro', 'freelancer', 'help', 'contact'],
    intents: ['contact mir alamin', 'get 1-on-1 security support']
  },
];

// Helper to render Wrench icon without importing another unused icon
function WrenchIconPlaceholder(props: any) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={props.size || 16}
      height={props.size || 16}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      {...props}
    >
      <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" />
    </svg>
  );
}

// -----------------------------------------------------------------------------
// Recent Navigation Tracker (localStorage: webcare_recent_nav)
// -----------------------------------------------------------------------------
const RECENT_NAV_KEY = 'webcare_recent_nav';
const MAX_RECENT_ITEMS = 5;

export interface RecentNavItem {
  id: string;
  timestamp: number;
}

export function getRecentNavItems(): NavigationItem[] {
  if (typeof window === 'undefined' || !window.localStorage) return [];
  try {
    const raw = localStorage.getItem(RECENT_NAV_KEY);
    if (!raw) return [];
    const parsed: RecentNavItem[] = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];

    const items: NavigationItem[] = [];
    for (const entry of parsed) {
      const match = NAVIGATION_CATALOG.find((it) => it.id === entry.id);
      if (match && !items.some((existing) => existing.id === match.id)) {
        items.push(match);
      }
    }
    return items.slice(0, MAX_RECENT_ITEMS);
  } catch {
    return [];
  }
}

export function recordRecentNav(id: string): void {
  if (typeof window === 'undefined' || !window.localStorage) return;
  try {
    const raw = localStorage.getItem(RECENT_NAV_KEY);
    let list: RecentNavItem[] = raw ? JSON.parse(raw) : [];
    if (!Array.isArray(list)) list = [];

    // Filter out current and prepend
    list = list.filter((it) => it.id !== id);
    list.unshift({ id, timestamp: Date.now() });

    if (list.length > MAX_RECENT_ITEMS) {
      list = list.slice(0, MAX_RECENT_ITEMS);
    }
    localStorage.setItem(RECENT_NAV_KEY, JSON.stringify(list));
  } catch {
    // Ignore storage failure
  }
}
