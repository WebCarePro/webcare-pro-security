=== WebCare Pro Security & Firewall ===
Contributors: miralamin
Tags: security, malware, ai-security, firewall, 2fa
Requires at least: 7.0
Tested up to: 7.1
Requires PHP: 8.3
Stable tag: 3.21.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Enterprise-grade WordPress security, malware detection, web application firewall (WAF), core integrity auditing, and threat intelligence.

== Description ==

WebCare Pro Security & Firewall gives you enterprise-grade malware detection, core integrity auditing, web application firewalling (WAF), session sentinel, rogue admin detection, and threat forensics inside an intuitive, modern React 18 single-page dashboard. Engineered by Mir Alamin (WebCare Pro) for high-performance WordPress sites, it provides deep visibility across your file system, WordPress core files, plugins, themes, database tables, cron jobs, active sessions, runtime hooks, and server configurations—without the performance bloat of traditional security tools.

Key highlights:
* **Deep Malware & Heuristic Scanner**: Scans PHP files, uploads, and database for webshells, backdoors, obfuscated injections, and rogue admin accounts.
* **WordPress Core & Plugin Integrity**: Cryptographic validation against official WordPress.org checksums with 1-click Auto-Cure.
* **Proactive Web Application Firewall (WAF)**: Zero-overhead request filtering, virtual patching, 404 rate-limiting, and Cloudflare Edge synchronization.
* **Zero Bloat & Memory-Safe Architecture**: Hierarchical cursors and adaptive resource governor preserve visitor headroom.
* **Pure AES-256-GCM Cryptographic Vault**: Encrypts sensitive secrets and TOTP 2FA keys at rest.
* **100% On-Premise & Privacy First**: Zero third-party telemetry, zero external tracking, and zero data collection.

== Screenshots ==

1. Cyber Command Center & Threat Dashboard with dynamic SVG Security Health Meter and 1-click audit console.
2. Multi-Vector Deep Malware Scanner showing real-time file inspection, heuristic detection, and issue classification.
3. Proactive Web Application Firewall (WAF) rule matrix with Layer 7 protection and real-time incident blocking.
4. Cloudflare Edge Defense dashboard showing Anycast edge sync, rate limiting, and automated IP ban integration.
5. In-Page Visual Code Diff Viewer Modal comparing altered files directly against pristine WordPress.org mirrors.
6. Session Sentinel & Live Device Manager providing real-time origin IP inspection and remote session revocation.

== Installation ==

1. Upload the `webcare-pro-security` folder to the `/wp-content/plugins/` directory, or install directly through the WordPress plugins dashboard.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Access your new cyber command center by clicking **WebCare Pro** in the admin sidebar.
4. Run your first Deep Audit from the Cyber Command Center.

== Frequently Asked Questions ==

= Does WebCare Pro Security & Firewall slow down my website? =
No. The scanner is built with a memory-safe batching engine that processes files in non-blocking chunks with zero impact on frontend visitors. The frontend admin interface runs on modern React 18 and only executes within the WordPress admin dashboard.

= What makes the Cryptographic Secret Vault different from other plugins? =
Standard WordPress plugins store sensitive credentials like webhook URLs and Cloudflare tokens in plaintext inside `wp_options`. WebCare Pro Security & Firewall encrypts all sensitive data at rest using pure AES-256-GCM AEAD encryption with 128-bit integrity tags. If your database is exported or leaked, attackers see only ciphertext.

= Can I use Cloudflare Free Plan with this plugin? =
Yes! WebCare Pro Security & Firewall provides 100% Free Plan compatible Cloudflare integration. It deploys 4 master compound rules, leaving 1 custom rule slot 100% free for site owner rules, plus edge rate limiting and bi-directional auto-ban synchronization.

= Does this plugin phone home or collect telemetry? =
No. WebCare Pro Security & Firewall contains zero tracking, zero telemetry, and zero analytics. All scans and security checks execute 100% locally on your server.

= What if I get locked out? How do I unblock myself? =
If your IP address gets temporarily blocked by login rate-limiting, honeypot traps, or firewall rules, you can immediately restore access using any of these simple methods:

1. Emergency wp-config.php Whitelist (Fastest & Recommended):
Add this single line to your wp-config.php file (above the "/* That's all, stop editing! */" line) with your public IP address:
define('WEBCAREPROSCAN_OVERRIDE_WHITELIST_IP', '203.0.113.1');
This grants an instantaneous, zero-delay bypass across all WAF and login hardening checks even if the database is inaccessible.

2. Emergency Firewall Bypass:
To temporarily disable all WAF inspection rules without deactivating the plugin:
define('WEBCAREPROSCAN_DISABLE_WAF', true);

3. Reset Login Lockouts via WP-CLI:
If you have SSH/terminal access, simply run:
wp option delete webcareproscan_login_lockouts

4. Database / phpMyAdmin:
In your database tool, browse the wp_options table and delete the option named webcareproscan_login_lockouts.

== External Services ==

This plugin can optionally connect to the following external third-party services to enhance security, provide checksum verification, and support optional AI forensics:

1. WordPress.org Checksum API
* Service: WordPress Foundation (https://api.wordpress.org/core/checksums/1.0/).
* Purpose: Compares installed WordPress Core files against official release checksums to detect modified or malicious core files.
* Data Sent: WordPress version string, locale, and site URL.
* When: Triggered when running Core Integrity checks or starting a Full Deep Audit.
* Terms of Service: https://wordpress.org/about/privacy/
* Privacy Policy: https://wordpress.org/about/privacy/

2. WordPress.org Subversion Repository Mirrors
* Service: WordPress Foundation (https://plugins.svn.wordpress.org and https://themes.svn.wordpress.org).
* Purpose: Fetches clean, authentic source code copies of official plugins and themes for side-by-side visual diffing (FIM).
* Data Sent: Plugin/theme slug, file path, and version number.
* When: Only on-demand when an administrator opens the Visual Diff Viewer.
* Terms of Service: https://wordpress.org/about/privacy/
* Privacy Policy: https://wordpress.org/about/privacy/

3. Blocklist.de & FireHOL Threat Intelligence Feeds
* Service: Blocklist.de (https://www.blocklist.de) and FireHOL (https://iplists.firehol.org).
* Purpose: Synchronizes known hostile botnet IPs, brute-force scanners, and malicious probe nodes to populate the local WAF threat database.
* Data Sent: None (outbound GET request to download public IP lists).
* When: Triggered on-demand when clicking "Sync Threat Feeds" or during scheduled background threat intelligence refreshes.
* Blocklist.de Terms: https://www.blocklist.de/en/tos.html
* Blocklist.de Privacy: https://www.blocklist.de/en/privacy.html

4. OpenAI API (Optional)
* Service: OpenAI, LLC (https://openai.com).
* Purpose: AI code analysis of suspicious code snippets.
* Data Sent: Code snippet, file path, threat signature, and administrator query.
* When: Only on-demand when the administrator inputs their own OpenAI API key and clicks "Analyze with AI".
* Terms of Service: https://openai.com/policies/terms-of-use
* Privacy Policy: https://openai.com/policies/privacy-policy

5. Google Gemini API (Optional)
* Service: Google LLC (https://ai.google.dev).
* Purpose: AI code analysis of suspicious code snippets.
* Data Sent: Code snippet, file path, threat signature, and administrator query.
* When: Only on-demand when the administrator inputs their own Gemini API key and clicks "Analyze with AI".
* Terms of Service: https://ai.google.dev/terms
* Privacy Policy: https://policies.google.com/privacy

6. Anthropic Claude API (Optional)
* Service: Anthropic, PBC (https://www.anthropic.com).
* Purpose: AI code analysis of suspicious code snippets.
* Data Sent: Code snippet, file path, threat signature, and administrator query.
* When: Only on-demand when the administrator inputs their own Anthropic API key and clicks "Analyze with AI".
* Terms of Service: https://www.anthropic.com/legal/consumer-terms
* Privacy Policy: https://www.anthropic.com/legal/privacy

7. Slack Webhook API (Optional)
* Service: Slack Technologies (https://slack.com).
* Purpose: Sends optional security incident notifications to the administrator's designated Slack channel.
* Data Sent: Alert notification message, site name, threat severity, and incident timestamp.
* When: Triggered only if configured and enabled by the administrator in Scanner Settings.
* Terms of Service: https://slack.com/terms-of-service
* Privacy Policy: https://slack.com/privacy-policy

8. Discord Webhook API (Optional)
* Service: Discord Inc. (https://discord.com).
* Purpose: Sends optional security incident notifications to the administrator's designated Discord channel.
* Data Sent: Alert notification embed card, site name, threat severity, and incident timestamp.
* When: Triggered only if configured and enabled by the administrator in Scanner Settings.
* Terms of Service: https://discord.com/terms
* Privacy Policy: https://discord.com/privacy

9. ClickUp Automation API (Optional)
* Service: ClickUp (https://clickup.com).
* Purpose: Creates automated DevSecOps tasks on critical security threats.
* Data Sent: Task name, description with site name, risk score, findings count, and incident timestamp.
* When: Only if configured and enabled by the administrator in Scanner Settings.
* Terms of Service: https://clickup.com/terms
* Privacy Policy: https://clickup.com/privacy

10. Asana API & Automations (Optional)
* Service: Asana Inc. (https://asana.com).
* Purpose: Creates automated project management tasks on security findings.
* Data Sent: Task name, forensic notes, site name, risk score, and incident timestamp.
* When: Only if configured and enabled by the administrator in Scanner Settings.
* Terms of Service: https://asana.com/terms
* Privacy Policy: https://asana.com/privacy

11. Generic Automation Webhooks (Zapier, Make.com, n8n) (Optional)
* Service: User-specified automation endpoints.
* Purpose: Dispatches structured JSON event payloads to trigger custom enterprise DevSecOps automation workflows.
* Data Sent: JSON event payload with event type, site name, site URL, risk score, issue count, and timestamp.
* When: Only if configured and enabled by the administrator in Scanner Settings.

12. Cloudflare API v4 (Optional)
* Service: Cloudflare Inc. (https://www.cloudflare.com).
* Purpose: Deploys edge WAF rules, wp-login rate limiting, and IP access block rules to Cloudflare CDN, and purges edge cache.
* Data Sent: Zone ID, WAF ruleset configurations, and blocked malicious IP addresses when explicitly initiated or configured for auto-sync.
* When: Only when the administrator enters their Cloudflare API Token and Zone ID in the Cloudflare Edge Defense tab.
* Terms of Service: https://www.cloudflare.com/terms/
* Privacy Policy: https://www.cloudflare.com/privacypolicy/

13. Have I Been Pwned API (HIBP)
* Service: Troy Hunt / Have I Been Pwned (https://haveibeenpwned.com).
* Purpose: Verifies whether user-submitted passwords or administrator accounts have been compromised in known global data breaches using k-Anonymity mathematical privacy model.
* Data Sent: Only the first 5 characters of the SHA-1 hash of the password (k-Anonymity prefix). The full password or hash is never transmitted over the network.
* When: Triggered during password audits or administrator login checks when HIBP Breach Shield is enabled.
* Terms of Service: https://haveibeenpwned.com/API/v3
* Privacy Policy: https://haveibeenpwned.com/Privacy

14. NIST National Vulnerability Database (NVD)
* Service: National Institute of Standards and Technology (NIST) (https://nvd.nist.gov).
* Purpose: Queries official CVE vulnerability descriptions and severity metrics for detected WordPress core, theme, and plugin vulnerabilities.
* Data Sent: CVE identification string (e.g. CVE-2023-XXXX). No user or website data is sent.
* When: Triggered on-demand when inspecting CVE threat details in the Vulnerabilities tab.
* Terms of Service: https://www.nist.gov/copyrights-disclaimers
* Privacy Policy: https://www.nist.gov/privacy-policy

15. Stamparm Ipsum & Threat Intelligence Feeds
* Service: Stamparm Ipsum Project (https://github.com/stamparm/ipsum).
* Purpose: Downloads curated feeds of suspicious IP addresses and known malicious scanners to update the local firewall blocklist.
* Data Sent: None (outbound GET request to download public IP lists).
* When: Triggered on-demand or during scheduled threat intelligence sync when enabled by administrator.
* Terms of Service: https://github.com/stamparm/ipsum/blob/master/README.md
* Privacy Policy: https://github.com/stamparm/ipsum

16. GitHub Content Delivery (Self-Defense Integrity Attestation)
* Service: GitHub, Inc. / Microsoft Corporation (https://github.com).
* Purpose: Checks plugin self-defense cryptographic manifest attestation against official repository releases.
* Data Sent: None (outbound GET request to fetch public plugin release manifest).
* When: Triggered only when verifying plugin self-defense integrity in the Forensics tab.
* Terms of Service: https://docs.github.com/en/site-policy/github-terms/github-terms-of-service
* Privacy Policy: https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement

17. Domain Reputation & DNSBL Threat Providers (Spamhaus, SURBL, SpamCop) (Optional)
* Service: Public Domain Name System Blacklist providers (Spamhaus https://www.spamhaus.org, SURBL https://www.surbl.org, SpamCop https://www.spamcop.net).
* Purpose: Queries domain and host IP reputation against public DNSBL zones to alert administrators if the site domain or server IP has been blacklisted for malware or spam distribution.
* Data Sent: Standard DNS query containing the reversed server IP address or site domain name. No personal user data or website content is ever transmitted.
* When: Triggered only when the administrator explicitly opts in to Domain Reputation Monitoring in Settings, or runs an on-demand audit in the Forensics tab.
* Spamhaus Terms: https://www.spamhaus.org/terms-of-use/
* Spamhaus Privacy: https://www.spamhaus.org/privacy-policy/
* SURBL Terms: https://www.surbl.org/terms-of-use
* SpamCop Privacy: https://www.spamcop.net/fom-serve/cache/37.html

== Source Code & Build ==

This plugin is open-source under GPLv2 or later. Non-minified React and JavaScript source files are included directly in the `src/` directory.

The public source repository is hosted on GitHub:
https://github.com/webcarepro/webcare-pro-security

To compile the React admin application from source:
1. Ensure Node.js 18+ and npm are installed.
2. In the plugin root, run `npm install`.
3. Run `npm run build` to generate the production bundle in `build/index.js`.
4. Run `npm run package` to compile and package the release zip.

== Changelog ==
