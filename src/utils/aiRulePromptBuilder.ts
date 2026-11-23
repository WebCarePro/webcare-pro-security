/**
 * Builds copy-ready, site-aware Markdown prompts for ChatGPT, Gemini, and Claude
 * so users can generate valid WebCare Pro Wirefilter expressions or JSON rule bundles
 * and paste them directly back into the Custom Firewall Rules builder.
 */

export interface AiPromptFieldSchema {
  id: string;
  label: string;
  ops: string[];
}

export interface AiPromptComponent {
  slug: string;
  name: string;
  version?: string;
  type: string;
  status: string;
  url_path: string;
}

export interface AiPromptRole {
  slug: string;
  label: string;
}

export interface AiPromptExistingRule {
  id: string;
  rule_number: number;
  priority: number;
  title: string;
  action_type: string;
  current_mode: string;
}

export interface AiPromptContextInput {
  userGoal?: string;
  fields: AiPromptFieldSchema[];
  installedComponents: AiPromptComponent[];
  roles: AiPromptRole[];
  existingRules: AiPromptExistingRule[];
  discoveredEndpoints: { ajax_actions: string[]; rest_routes: string[] };
  cfProxied: boolean;
}

export function buildAiRuleMarkdownPrompt(input: AiPromptContextInput): string {
  const goal = (input.userGoal || '').trim();
  const origin = typeof window !== 'undefined' ? window.location.origin : '';

  const lines: string[] = [
    '# WebCare Pro Custom Firewall Rule Request',
    '',
    'Please write a firewall rule for my WordPress website using **ONLY** the supported fields and operators listed below.',
    '',
    '## What I Want to Achieve',
    goal || '[Replace this line with your plain-English request, e.g., "Block guest file uploads to PHP scripts" or "Allow only logged-in admins to access /wp-json/custom/v1/"]',
    '',
    '## Site Environment & Safety Guardrails',
    `- WordPress Site: \`${origin || 'https://example.com'}\``,
    `- Cloudflare Proxy Headers (\`CF-IPCountry\` / \`CF-IPASN\`): ${
      input.cfProxied
        ? 'ACTIVE'
        : 'NOT ACTIVE on current origin — do NOT rely on `ip.geoip.country` or `ip.geoip.asnum`'
    }`,
    '- NEVER lock out site administrators: when restricting `/wp-admin/`, `/wp-login.php`, or admin endpoints, exclude logged-in users (`not wp.user.is_logged_in`).',
    '',
    '## Supported Fields & Operators (18 Fields)',
  ];

  for (const f of input.fields) {
    lines.push(`- \`${f.id}\` (${f.label}): \`${(f.ops || []).join(', ')}\``);
  }

  if (input.installedComponents.length > 0) {
    lines.push('', '## Installed Plugins & Themes on This Site');
    for (const c of input.installedComponents.slice(0, 35)) {
      lines.push(
        `- \`${c.slug}\` (${c.status}, v${c.version || '0'}) -> path \`${c.url_path}\``
      );
    }
  }

  if (input.roles.length > 0) {
    lines.push('', '## WordPress Roles');
    lines.push(input.roles.map((r) => `\`${r.slug}\``).join(', '));
  }

  if (input.discoveredEndpoints.ajax_actions.length > 0) {
    lines.push('', '## Discovered Guest AJAX Actions (Sample)');
    lines.push(
      input.discoveredEndpoints.ajax_actions
        .slice(0, 20)
        .map((a) => `\`${a}\``)
        .join(', ')
    );
  }

  if (input.discoveredEndpoints.rest_routes.length > 0) {
    lines.push('', '## Discovered REST Routes (Sample)');
    lines.push(
      input.discoveredEndpoints.rest_routes
        .slice(0, 20)
        .map((r) => `\`${r}\``)
        .join(', ')
    );
  }

  if (input.existingRules.length > 0) {
    lines.push('', '## Existing Custom Rules (Avoid Duplicates)');
    for (const r of input.existingRules.slice(0, 20)) {
      lines.push(`- Order #${r.priority} (ID #${r.rule_number}): ${r.title} [${r.action_type}]`);
    }
  }

  lines.push(
    '',
    '## Required Output Format',
    'Reply with **ONE** code block below so I can paste it straight into WebCare Pro:',
    '',
    '### Preferred Option A — Complete JSON Rule (Auto-fills Name, Expression & Action)',
    '```json',
    '{',
    '  "title": "Short rule name",',
    '  "description": "Plain-English note",',
    '  "expression": "(http.request.uri.path contains \\"/wp-content/plugins/example/\\" and not wp.user.is_logged_in)",',
    '  "action_type": "block",',
    '  "ban_ttl": 86400,',
    '  "block_uploads": true,',
    '  "placement": "last"',
    '}',
    '```',
    '*(Valid `action_type`: `block`, `block_and_ban`, `rate_limit`, `challenge_pow`, `payload_inspect`, `monitor`, `allow`)*',
    '',
    '### Option B — Expression Only',
    '```wirefilter',
    '(http.request.method eq "POST" and wp.user.is_logged_in eq false)',
    '```'
  );

  return lines.join('\n');
}
