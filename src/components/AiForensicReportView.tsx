import { useState, useMemo } from '@wordpress/element';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  Terminal,
  FileCode,
  Copy,
  Check,
  Eye,
  Info,
  Sparkles,
  ExternalLink,
  Shield,
  HelpCircle,
  Wrench,
  UserCheck
} from 'lucide-react';

interface AiForensicReportViewProps {
  analysis: string;
  provider?: string | null;
  model?: string | null;
  filePath?: string;
  threatType?: string;
}

/**
 * Enhanced AI Threat & Forensic Code Analysis Report Component
 * Accurately classifies whether a file is truly Malware or Safe/Legitimate,
 * preventing false alarms on benign developer configs or theme modifications.
 */
export default function AiForensicReportView({
  analysis,
  provider,
  model,
  filePath,
  threatType,
}: AiForensicReportViewProps) {
  const [viewMode, setViewMode] = useState<'visual' | 'raw'>('visual');
  const [copiedFull, setCopiedFull] = useState(false);

  // Extract Verdict, Severity, and Key Metrics with precision
  const metadata = useMemo(() => {
    const text = analysis || '';

    // 1. Precise Threat Verdict extraction
    // Targets the explicit "Threat Verdict" or "Threat Assessment" line rather than loose keywords
    const verdictMatch = text.match(/(?:threat\s*verdict|threat\s*assessment|verdict)\s*:\s*(?:\*\*)?([^\n\*\r\(\)]+)(?:\*\*)?/i);
    const parsedVerdict = verdictMatch ? verdictMatch[1].trim().toLowerCase() : '';

    // Check malicious tokens FIRST with word boundaries (prevents "unsafe" being matched as "safe", etc.)
    const isMalicious = /\b(malicious|backdoor|webshell|trojan|exploit|unsafe|compromised|critical|payload|rootkit|phishing)\b/i.test(parsedVerdict);

    // Check suspicious tokens next
    const isSuspicious = !isMalicious && /\b(suspicious|anomaly|violation|warning|unverified|canary|caution|tampered)\b/i.test(parsedVerdict);

    // Check safe tokens ONLY if neither malicious nor suspicious, ensuring no negations ("not a false positive", "not clean", "unsafe")
    const isSafe = !isMalicious && !isSuspicious && (
      /(?<!not\s+|not\s+a\s+|un|in)\b(safe|legitimate|clean|benign|false\s+positive|verified)\b/i.test(parsedVerdict)
    );

    let verdict: 'malicious' | 'suspicious' | 'safe' = 'safe';
    let verdictLabel = 'Safe & Legitimate Code (No Malware)';

    if (isMalicious) {
      verdict = 'malicious';
      verdictLabel = 'Malicious Threat Detected';
    } else if (isSuspicious) {
      verdict = 'suspicious';
      verdictLabel = 'Suspicious Anomaly (Review Recommended)';
    } else if (isSafe) {
      verdict = 'safe';
      verdictLabel = 'Safe & Legitimate Code (No Malware)';
    } else {
      // Fallback: Check the Executive Summary (first 450 chars) with negative lookbehinds
      const intro = text.slice(0, 450).toLowerCase();
      const introMalicious = /\b(malicious|backdoor|webshell|trojan|exploit|unsafe|compromised)\b/i.test(intro);
      const introSuspicious = !introMalicious && /\b(suspicious|anomaly|violation|warning)\b/i.test(intro);
      const introSafe = !introMalicious && !introSuspicious && (
        /(?<!not\s+|not\s+a\s+|un|in)\b(safe|clean|legitimate|benign|false\s+positive)\b/i.test(intro)
      );

      if (introMalicious) {
        verdict = 'malicious';
        verdictLabel = 'Malicious Threat Detected';
      } else if (introSuspicious) {
        verdict = 'suspicious';
        verdictLabel = 'Suspicious Anomaly (Review Recommended)';
      } else if (introSafe) {
        verdict = 'safe';
        verdictLabel = 'Safe & Legitimate Code (No Malware)';
      } else {
        verdict = 'suspicious';
        verdictLabel = 'Suspicious Anomaly (Review Recommended)';
      }
    }

    // 2. Precise Risk Severity extraction
    const sevMatch = text.match(/(?:risk\s*severity|severity\s*level|severity)\s*:\s*(?:\*\*)?([A-Za-z]+)(?:\*\*)?/i);
    const parsedSev = sevMatch ? sevMatch[1].trim().toLowerCase() : '';

    let severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Clean' = 'Clean';
    if (parsedSev.includes('crit')) severity = 'Critical';
    else if (parsedSev.includes('high')) severity = 'High';
    else if (parsedSev.includes('med')) severity = 'Medium';
    else if (parsedSev.includes('low')) severity = 'Low';
    else if (parsedSev.includes('clean') || parsedSev.includes('safe')) severity = 'Clean';
    else {
      if (verdict === 'malicious') severity = 'High';
      else if (verdict === 'suspicious') severity = 'Low';
      else severity = 'Clean';
    }

    return { verdict, verdictLabel, severity };
  }, [analysis]);

  // Copy helper
  const handleCopyFull = () => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(analysis);
      setCopiedFull(true);
      setTimeout(() => setCopiedFull(false), 2000);
    }
  };

  /**
   * Helper that splits text and applies exact contextual styling:
   * 1. Highlight detected code and numbers in RED and BOLD text with light red background
   * 2. Highlight safe/legitimate terms in SOFT GREEN background
   * 3. Highlight suspicious concepts in YELLOW background
   * 4. Highlight malicious terms in RED background
   */
  const renderHighlightedContent = (rawText: string) => {
    if (!rawText) return null;

    // Pattern matches:
    // Group 1: Backticked code: `code_snippet`
    // Group 2: Explicit line numbers: (?:lines?|line\s+number)\s+#?\d+(?:[–-]\d+)?
    // Group 3: Safe / Legitimate terms
    // Group 4: Suspicious / Warning terms
    // Group 5: Malicious terms
    const tokenRegex = /(`[^`]+`)|(\b(?:lines?|line\s+number)\s+#?\d+(?:[–-]\d+)?\b)|(\b(?:Safe\s*\/\s*False\s*Positive|False\s*Positive|Legitimate|Clean|Benign|Safe)\b)|(\b(?:Suspicious|Integrity\s*Violation|Potential\s*Canary|Canaries|Canary|Direct\s*Execution\s*Risk|Environmental\s*Risk|Unauthorized\s*Write|Tampering|Remediation|Action\s*Required)\b)|(\b(?:Malicious|Backdoor|Webshell|Trojan|Exploit)\b)/gi;

    const lines = rawText.split('\n');

    return lines.map((line, lineIdx) => {
      // Check if line is a markdown section header
      const headerMatch = line.match(/^(#{1,4})\s+(.+)$/);
      if (headerMatch) {
        const titleText = headerMatch[2].replace(/\*\*/g, '').trim();
        return (
          <div
            key={lineIdx}
            style={{
              marginTop: lineIdx === 0 ? '0' : '22px',
              marginBottom: '10px',
              paddingBottom: '8px',
              borderBottom: '1px solid #e2e8f0',
              display: 'flex',
              alignItems: 'center',
              gap: '8px'
            }}
          >
            <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#7c3aed' }} />
            <h4 style={{ margin: 0, fontSize: '15px', color: '#1e293b', fontWeight: 700 }}>
              {titleText}
            </h4>
          </div>
        );
      }

      // Check if line is a horizontal rule
      if (/^---+$/.test(line.trim())) {
        return <hr key={lineIdx} style={{ border: 'none', borderTop: '1px solid #e2e8f0', margin: '16px 0' }} />;
      }

      // Check if line is a bullet item
      const isBullet = /^\s*[\*\-]\s+/.test(line);
      const cleanLine = isBullet ? line.replace(/^\s*[\*\-]\s+/, '') : line;

      if (!cleanLine.trim()) {
        return <div key={lineIdx} style={{ height: '8px' }} />;
      }

      const parts: any[] = [];
      let lastIndex = 0;
      let match: RegExpExecArray | null;
      tokenRegex.lastIndex = 0;

      while ((match = tokenRegex.exec(cleanLine)) !== null) {
        if (match.index > lastIndex) {
          parts.push(cleanLine.substring(lastIndex, match.index));
        }

        const [fullMatch, codeMatch, lineNumMatch, safeMatch, suspMatch, malMatch] = match;

        if (codeMatch) {
          // Detected code snippet in backticks -> RED and BOLD
          const codeSnippet = codeMatch.slice(1, -1);
          parts.push(
            <span
              key={`code-${lineIdx}-${match.index}`}
              style={{
                color: '#b91c1c',
                background: '#fee2e2',
                border: '1px solid #fca5a5',
                fontWeight: 700,
                padding: '1px 6px',
                borderRadius: '4px',
                fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
                fontSize: '12.5px',
                display: 'inline-block',
                margin: '1px 2px'
              }}
            >
              {codeSnippet}
            </span>
          );
        } else if (lineNumMatch) {
          // Line number reference -> RED and BOLD
          parts.push(
            <span
              key={`num-${lineIdx}-${match.index}`}
              style={{
                color: '#b91c1c',
                background: '#fef2f2',
                border: '1px solid #fecaca',
                fontWeight: 800,
                padding: '1px 6px',
                borderRadius: '4px',
                fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
                fontSize: '12.5px',
                display: 'inline-block',
                margin: '1px 2px'
              }}
            >
              {fullMatch}
            </span>
          );
        } else if (safeMatch) {
          // Safe / Legitimate terms -> SOFT GREEN BACKGROUND HIGHLIGHT
          parts.push(
            <span
              key={`safe-${lineIdx}-${match.index}`}
              style={{
                background: '#dcfce7',
                color: '#166534',
                border: '1px solid #86efac',
                fontWeight: 700,
                padding: '1px 6px',
                borderRadius: '4px',
                display: 'inline-block',
                margin: '1px 2px'
              }}
            >
              {fullMatch}
            </span>
          );
        } else if (suspMatch) {
          // Suspicious / Warning terms -> YELLOW BACKGROUND HIGHLIGHT
          parts.push(
            <span
              key={`susp-${lineIdx}-${match.index}`}
              style={{
                background: '#fef08a',
                color: '#713f12',
                border: '1px solid #fde047',
                fontWeight: 700,
                padding: '1px 6px',
                borderRadius: '4px',
                display: 'inline-block',
                margin: '1px 2px'
              }}
            >
              {fullMatch}
            </span>
          );
        } else if (malMatch) {
          // Malicious / Exploit terms -> RED BACKGROUND HIGHLIGHT
          parts.push(
            <span
              key={`mal-${lineIdx}-${match.index}`}
              style={{
                background: '#fee2e2',
                color: '#991b1b',
                border: '1px solid #fca5a5',
                fontWeight: 700,
                padding: '1px 6px',
                borderRadius: '4px',
                display: 'inline-block',
                margin: '1px 2px'
              }}
            >
              {fullMatch}
            </span>
          );
        }

        lastIndex = match.index + fullMatch.length;
      }

      if (lastIndex < cleanLine.length) {
        parts.push(cleanLine.substring(lastIndex));
      }

      // Convert any leftover markdown bold markers **text** into <strong>
      const renderedParts = parts.map((part, pIdx) => {
        if (typeof part !== 'string') return part;
        const subChunks = part.split(/(\*\*[^*]+\*\*)/g);
        return subChunks.map((sub, sIdx) => {
          if (sub.startsWith('**') && sub.endsWith('**')) {
            const boldText = sub.slice(2, -2);
            return (
              <strong key={`b-${pIdx}-${sIdx}`} style={{ color: '#0f172a', fontWeight: 700 }}>
                {boldText}
              </strong>
            );
          }
          return sub;
        });
      });

      return (
        <div
          key={lineIdx}
          style={{
            fontSize: '13.5px',
            lineHeight: 1.7,
            color: '#334155',
            marginBottom: '4px',
            display: isBullet ? 'flex' : 'block',
            alignItems: isBullet ? 'flex-start' : undefined,
            gap: isBullet ? '8px' : undefined
          }}
        >
          {isBullet && (
            <span
              style={{
                width: '6px',
                height: '6px',
                borderRadius: '50%',
                background: '#6366f1',
                marginTop: '8px',
                flexShrink: 0
              }}
            />
          )}
          <div style={{ flex: 1 }}>{renderedParts}</div>
        </div>
      );
    });
  };

  // Severity color definitions
  const severityColors = {
    Critical: { bg: '#dc2626', text: '#fff' },
    High:     { bg: '#e11d48', text: '#fff' },
    Medium:   { bg: '#d97706', text: '#fff' },
    Low:      { bg: '#059669', text: '#fff' },
    Clean:    { bg: '#10b981', text: '#fff' },
  }[metadata.severity];

  // Verdict theme definitions
  const verdictTheme = {
    malicious: {
      bg: 'linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%)',
      border: '#fca5a5',
      badgeBg: '#dc2626',
      badgeText: '#fff',
      titleColor: '#991b1b',
      icon: <ShieldAlert size={22} color="#dc2626" />,
      advice: 'Critical Alert: Hostile malware or backdoor detected. Quarantine or remove this file immediately.'
    },
    suspicious: {
      bg: 'linear-gradient(135deg, #fffbeb 0%, #fef3c7 100%)',
      border: '#fcd34d',
      badgeBg: '#d97706',
      badgeText: '#fff',
      titleColor: '#92400e',
      icon: <AlertTriangle size={22} color="#d97706" />,
      advice: 'Review Recommended: An unusual setting or modified file was found, but it is NOT active malware.'
    },
    safe: {
      bg: 'linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%)',
      border: '#86efac',
      badgeBg: '#16a34a',
      badgeText: '#fff',
      titleColor: '#166534',
      icon: <ShieldCheck size={22} color="#16a34a" />,
      advice: 'Verified Safe: No malicious code found. This is legitimate code and your site is not in danger.'
    }
  }[metadata.verdict];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* View Switcher & Action Bar */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '10px',
          background: '#f8fafc',
          border: '1px solid #e2e8f0',
          padding: '10px 14px',
          borderRadius: '10px'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <button
            type="button"
            onClick={() => setViewMode('visual')}
            style={{
              background: viewMode === 'visual' ? '#7c3aed' : '#fff',
              color: viewMode === 'visual' ? '#fff' : '#475569',
              border: '1px solid ' + (viewMode === 'visual' ? '#7c3aed' : '#cbd5e1'),
              padding: '5px 12px',
              borderRadius: '6px',
              fontSize: '12px',
              fontWeight: 600,
              cursor: 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px'
            }}
          >
            <Sparkles size={13} />
            Executive Visual Report
          </button>
          <button
            type="button"
            onClick={() => setViewMode('raw')}
            style={{
              background: viewMode === 'raw' ? '#7c3aed' : '#fff',
              color: viewMode === 'raw' ? '#fff' : '#475569',
              border: '1px solid ' + (viewMode === 'raw' ? '#7c3aed' : '#cbd5e1'),
              padding: '5px 12px',
              borderRadius: '6px',
              fontSize: '12px',
              fontWeight: 600,
              cursor: 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px'
            }}
          >
            <Terminal size={13} />
            Raw Markdown Output
          </button>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <button
            type="button"
            onClick={handleCopyFull}
            style={{
              background: '#fff',
              color: copiedFull ? '#16a34a' : '#475569',
              border: '1px solid #cbd5e1',
              padding: '5px 12px',
              borderRadius: '6px',
              fontSize: '12px',
              fontWeight: 600,
              cursor: 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px'
            }}
            title="Copy full forensic report to clipboard"
          >
            {copiedFull ? <Check size={13} color="#16a34a" /> : <Copy size={13} />}
            {copiedFull ? 'Copied Full Report!' : 'Copy Report'}
          </button>
        </div>
      </div>

      {viewMode === 'visual' ? (
        <>
          {/* Executive Verdict Summary Card */}
          <div
            style={{
              background: verdictTheme.bg,
              border: `1px solid ${verdictTheme.border}`,
              borderRadius: '12px',
              padding: '18px 20px',
              display: 'flex',
              flexDirection: 'column',
              gap: '12px',
              boxShadow: '0 2px 4px rgba(0,0,0,0.03)'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div style={{ background: 'var(--webcare-bg-card, #fff)', padding: '6px', borderRadius: '8px', border: `1px solid ${verdictTheme.border}`, display: 'flex' }}>
                  {verdictTheme.icon}
                </div>
                <div>
                  <div style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.5px', fontWeight: 700, color: '#64748b' }}>
                    Cybersecurity Forensic Verdict
                  </div>
                  <h3 style={{ margin: '2px 0 0 0', fontSize: '17px', color: verdictTheme.titleColor, fontWeight: 700 }}>
                    {metadata.verdictLabel}
                  </h3>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span
                  style={{
                    background: severityColors.bg,
                    color: severityColors.text,
                    padding: '3px 10px',
                    borderRadius: '12px',
                    fontSize: '12px',
                    fontWeight: 700,
                    textTransform: 'uppercase'
                  }}
                >
                  Severity: {metadata.severity}
                </span>
                {provider && (
                  <span
                    style={{
                      background: '#ede9fe',
                      color: '#6b21a8',
                      padding: '3px 10px',
                      borderRadius: '12px',
                      fontSize: '11px',
                      fontWeight: 600
                    }}
                  >
                    Engine: {provider.toUpperCase()}
                  </span>
                )}
              </div>
            </div>

            <p style={{ margin: 0, fontSize: '13px', color: verdictTheme.titleColor, lineHeight: 1.5, fontWeight: 500 }}>
              {verdictTheme.advice}
            </p>
          </div>

          {/* Easy Color Guide for Non-Technical Users */}
          <div
            style={{
              background: '#f8fafc',
              border: '1px solid #e2e8f0',
              borderRadius: '8px',
              padding: '8px 14px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '10px',
              fontSize: '12px'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 600, color: '#334155' }}>
              <HelpCircle size={14} color="#6366f1" />
              <span>Color Guide:</span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#16a34a', display: 'inline-block' }} />
                <span style={{ fontWeight: 600, color: '#166534' }}>Green:</span>
                <span style={{ color: '#475569' }}>Safe / Normal</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#eab308', display: 'inline-block' }} />
                <span style={{ fontWeight: 600, color: '#854d0e' }}>Yellow:</span>
                <span style={{ color: '#475569' }}>Needs Review</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#dc2626', display: 'inline-block' }} />
                <span style={{ fontWeight: 600, color: '#991b1b' }}>Red:</span>
                <span style={{ color: '#475569' }}>Detected Code / Threat</span>
              </div>
            </div>
          </div>

          {/* Structured Intelligence Card with Formatted Text */}
          <div
            style={{
              background: '#ffffff',
              border: '1px solid #e2e8f0',
              borderRadius: '12px',
              padding: '24px',
              boxShadow: '0 1px 3px rgba(0,0,0,0.04)'
            }}
          >
            {renderHighlightedContent(analysis)}
          </div>
        </>
      ) : (
        /* Raw Terminal View */
        <div
          style={{
            background: '#090d16',
            color: '#e2e8f0',
            padding: '24px',
            borderRadius: '10px',
            fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
            fontSize: '13px',
            lineHeight: 1.7,
            whiteSpace: 'pre-wrap',
            overflowX: 'auto',
            border: '1px solid #1e293b'
          }}
        >
          {analysis}
        </div>
      )}
    </div>
  );
}
