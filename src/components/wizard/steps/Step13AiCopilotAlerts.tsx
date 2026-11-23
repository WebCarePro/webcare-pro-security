import React, { useState } from 'react';
import {
  Bell,
  Mail,
  Send,
  Sparkles,
  CheckCircle2,
  AlertCircle,
  Loader2,
  ExternalLink,
  Cpu,
  Eye,
  EyeOff,
  Zap,
  Check
} from 'lucide-react';
import { DeveloperDeepDive } from '../DeveloperDeepDive';
import { apiRequest } from '../../../utils/api';

interface Step13Props {
  scanSchedule: string;
  setScanSchedule: (val: string) => void;
  alertEmail: string;
  setAlertEmail: (email: string) => void;
  alerts: {
    notify_critical: boolean;
    notify_logins: boolean;
    notify_panic: boolean;
    notify_waf_lockout_spike?: boolean;
    notify_plugin_vulns?: boolean;
    weekly_digest_enabled?: boolean;
  };
  setAlerts: React.Dispatch<React.SetStateAction<any>>;
  slackWebhookUrl: string;
  setSlackWebhookUrl: (url: string) => void;
  discordWebhookUrl: string;
  setDiscordWebhookUrl: (url: string) => void;
  customWebhookUrl: string;
  setCustomWebhookUrl: (url: string) => void;
  aiProvider: string;
  setAiProvider: (provider: string) => void;
  aiApiKey: string;
  setAiApiKey: (key: string) => void;
  aiModel: string;
  setAiModel: (model: string) => void;
}

export const Step13AiCopilotAlerts: React.FC<Step13Props> = ({
  scanSchedule,
  setScanSchedule,
  alertEmail,
  setAlertEmail,
  alerts,
  setAlerts,
  slackWebhookUrl,
  setSlackWebhookUrl,
  discordWebhookUrl,
  setDiscordWebhookUrl,
  customWebhookUrl,
  setCustomWebhookUrl,
  aiProvider = 'gemini',
  setAiProvider,
  aiApiKey,
  setAiApiKey,
  aiModel,
  setAiModel,
}) => {
  const [sendingTest, setSendingTest] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);

  const [testingAi, setTestingAi] = useState(false);
  const [aiTestResult, setAiTestResult] = useState<{ success: boolean; message: string } | null>(null);
  const [showKey, setShowKey] = useState(false);

  // 2026 Latest AI Models & Providers Catalog
  const aiProviders = [
    {
      id: 'gemini',
      name: 'Google Gemini',
      tagline: 'Gemini 3.5 Flash-Lite / 3.8 Flash',
      defaultModel: 'gemini-3.5-flash-lite',
      keyPlaceholder: 'AIzaSy... (Google AI Studio Key)',
      keyUrl: 'https://aistudio.google.com/app/apikey',
      models: [
        { id: 'gemini-3.5-flash-lite', name: 'Gemini 3.5 Flash-Lite', desc: 'Recommended Low-Token & High-Speed Engine' },
        { id: 'gemini-3.8-flash', name: 'Gemini 3.8 Flash', desc: 'High-Intelligence Full Flagship Agent' },
        { id: 'gemini-3.1-flash-lite', name: 'Gemini 3.1 Flash-Lite', desc: 'Fast & Cost-Efficient Forensic Agent' },
        { id: 'gemini-2.5-flash', name: 'Gemini 2.5 Flash', desc: 'Balanced Multimodal Threat Inspector' },
      ],
    },
    {
      id: 'openai',
      name: 'OpenAI',
      tagline: 'GPT-6.1 Sol / GPT-6 Astra',
      defaultModel: 'gpt-6.1-sol',
      keyPlaceholder: 'sk-... (OpenAI Platform Key)',
      keyUrl: 'https://platform.openai.com/api-keys',
      models: [
        { id: 'gpt-6.1-sol', name: 'GPT-6.1 Sol', desc: 'Latest Balanced Default - Optimal Code Forensics & Speed' },
        { id: 'gpt-6-astra', name: 'GPT-6 Astra', desc: 'Flagship Frontier Model - Deep De-obfuscation & Autonomous Reasoning' },
        { id: 'gpt-6-luna', name: 'GPT-6 Luna', desc: 'Ultra-Fast Lightweight Model for High Volume Checks' },
        { id: 'gpt-4o', name: 'GPT-4o', desc: 'Multimodal Flagship' },
        { id: 'gpt-4o-mini', name: 'GPT-4o Mini', desc: 'Cost-Efficient Fast Model' },
      ],
    },
    {
      id: 'claude',
      name: 'Anthropic Claude',
      tagline: 'Claude Sonnet 5.5 / Opus 5.5',
      defaultModel: 'claude-sonnet-5-5',
      keyPlaceholder: 'sk-ant-... (Anthropic Console Key)',
      keyUrl: 'https://console.anthropic.com/settings/keys',
      models: [
        { id: 'claude-sonnet-5-5', name: 'Claude Sonnet 5.5', desc: 'Latest Default - Superior Code Analysis & Security Insights' },
        { id: 'claude-opus-5-5', name: 'Claude Opus 5.5', desc: 'Flagship Powerhouse for Complex Cryptographic Audits' },
        { id: 'claude-haiku-5-5', name: 'Claude Haiku 5.5', desc: 'Ultra-Low Latency Response for Quick File Checks' },
        { id: 'claude-3-7-sonnet', name: 'Claude 3.7 Sonnet', desc: 'Hybrid Reasoning & Deep Security Analysis' },
      ],
    },
    {
      id: 'wp_ai_connect',
      name: 'WordPress Native AI Connect',
      tagline: 'AI Engine / Local LLM (Zero-Config)',
      defaultModel: 'wp-native-ai',
      keyPlaceholder: 'No API key required (Uses active local engine)',
      keyUrl: '',
      models: [
        { id: 'wp-native-ai', name: 'WordPress Native AI Client', desc: 'Uses installed AI Engine, Ollama, or local WordPress AI pipeline' },
      ],
    },
    {
      id: 'deepseek',
      name: 'DeepSeek',
      tagline: 'DeepSeek-V3 / DeepSeek-R1',
      defaultModel: 'deepseek-chat',
      keyPlaceholder: 'sk-... (DeepSeek API Key)',
      keyUrl: 'https://platform.deepseek.com/api_keys',
      models: [
        { id: 'deepseek-chat', name: 'DeepSeek-V3', desc: 'Cost-Effective High-Throughput Forensic Reasoning' },
        { id: 'deepseek-reasoner', name: 'DeepSeek-R1', desc: 'Deep Chain-of-Thought Malware De-obfuscation' },
      ],
    },
    {
      id: 'openrouter',
      name: 'OpenRouter',
      tagline: 'Multi-Model Unified Gateway',
      defaultModel: 'auto',
      keyPlaceholder: 'sk-or-... (OpenRouter API Key)',
      keyUrl: 'https://openrouter.ai/keys',
      models: [
        { id: 'auto', name: 'OpenRouter Auto (Best Available)', desc: 'Automatically routes to lowest-latency available model' },
        { id: 'anthropic/claude-3.5-sonnet', name: 'Claude 3.5 Sonnet', desc: 'Via OpenRouter API' },
        { id: 'openai/gpt-4o', name: 'GPT-4o', desc: 'Via OpenRouter API' },
      ],
    },
  ];

  const currentProviderConfig = aiProviders.find((p) => p.id === aiProvider) || aiProviders[0];

  const handleProviderSelect = (provId: string) => {
    setAiProvider(provId);
    const target = aiProviders.find((p) => p.id === provId);
    if (target) {
      setAiModel(target.defaultModel);
    }
    setAiTestResult(null);
  };

  const handleSendTestAlert = async () => {
    setSendingTest(true);
    setTestResult(null);
    try {
      const res = await apiRequest({
        path: '/notifications/test-event',
        method: 'POST',
        data: {
          event_key: 'scan_threats_found',
          email: alertEmail.trim() || undefined,
          slack_webhook: slackWebhookUrl.trim() || undefined,
          discord_webhook: discordWebhookUrl.trim() || undefined,
          custom_webhook: customWebhookUrl.trim() || undefined,
        },
      });
      if (res && res.success) {
        setTestResult({
          success: true,
          message: res.message || 'Test alert dispatched successfully across configured channels!',
        });
      } else {
        setTestResult({
          success: false,
          message: res?.message || 'Could not send test alert. Check email server or webhook URL validity.',
        });
      }
    } catch (e: any) {
      setTestResult({
        success: false,
        message: e?.message || 'Failed to dispatch test notification event.',
      });
    } finally {
      setSendingTest(false);
    }
  };

  const handleTestAiConnection = async () => {
    setTestingAi(true);
    setAiTestResult(null);
    try {
      const res = await apiRequest({
        path: '/ai/test',
        method: 'POST',
        data: {
          provider: aiProvider,
          api_key: aiApiKey.trim() || undefined,
          model: aiModel || currentProviderConfig.defaultModel,
        },
      });

      if (res && res.success) {
        setAiTestResult({
          success: true,
          message: res.message || `Connected to ${currentProviderConfig.name} (${aiModel || currentProviderConfig.defaultModel}) successfully!`,
        });
      } else {
        setAiTestResult({
          success: false,
          message: res?.error || res?.message || 'AI connection test failed. Please verify your API key.',
        });
      }
    } catch (e: any) {
      setAiTestResult({
        success: false,
        message: e?.message || 'Error communicating with AI verification endpoint.',
      });
    } finally {
      setTestingAi(false);
    }
  };

  return (
    <div className="webcare-wizard-step-container" style={{ display: 'flex', flexDirection: 'column', gap: '24px', width: '100%', minWidth: 0, boxSizing: 'border-box' }}>
      {/* Step Header */}
      <div>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '4px 10px', borderRadius: '20px', background: 'var(--webcare-primary-soft, rgba(79, 70, 229, 0.08))', color: 'var(--webcare-primary, #4f46e5)', fontSize: '12px', fontWeight: 700, marginBottom: '12px' }}>
          <Bell size={14} /> Phase 4: Scanner &amp; SOC Telemetry
        </div>
        <h1 style={{ margin: '0 0 10px 0', fontSize: '24px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)' }}>
          AI Security Copilot &amp; Multi-Channel SOC Alerts
        </h1>
        <p style={{ fontSize: '14px', lineHeight: 1.6, color: 'var(--webcare-text-secondary, #475569)', margin: 0 }}>
          Configure automated scanning cadences, multi-channel incident dispatches for Slack, Discord, webhooks, and connect state-of-the-art AI threat reasoning.
        </p>
      </div>

      {/* Automated Scan Schedule */}
      <div style={{ padding: '20px', borderRadius: '12px', background: 'var(--webcare-bg-panel, #ffffff)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
        <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)', marginBottom: '12px' }}>
          Automated Scan Schedule
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '10px' }}>
          {[
            { id: 'daily', label: 'Daily (Recommended)', desc: 'Full scan every night during low traffic' },
            { id: 'twice_daily', label: 'Twice Daily', desc: 'Every 12 hours for high-velocity stores' },
            { id: 'weekly', label: 'Weekly', desc: 'Lightweight weekly checkup' },
            { id: 'manual', label: 'Manual Only', desc: 'Scan only on manual administrator trigger' },
          ].map((s) => (
            <div
              key={s.id}
              onClick={() => setScanSchedule(s.id)}
              style={{
                padding: '12px 14px',
                borderRadius: '8px',
                cursor: 'pointer',
                border: scanSchedule === s.id ? '2px solid var(--webcare-primary, #4f46e5)' : '1px solid var(--webcare-border, #e2e8f0)',
                background: scanSchedule === s.id ? 'var(--webcare-primary-soft, rgba(79, 70, 229, 0.04))' : 'var(--webcare-bg-elevated, #f8fafc)',
              }}
            >
              <div style={{ fontSize: '13px', fontWeight: 700, color: scanSchedule === s.id ? 'var(--webcare-primary, #4f46e5)' : 'var(--webcare-text-title, #0f172a)' }}>
                {s.label}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px', lineHeight: 1.3 }}>
                {s.desc}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Multi-Channel Alerts & Test Button */}
      <div style={{ padding: '20px', borderRadius: '12px', background: 'var(--webcare-bg-elevated, #f8fafc)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', flexWrap: 'wrap', gap: '8px' }}>
          <div>
            <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
              SOC Alert Channels &amp; Instant Verifier
            </div>
            <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '2px' }}>
              Dispatch real-time alerts when high-confidence malware or suspicious logins are detected.
            </div>
          </div>
          <button
            type="button"
            onClick={handleSendTestAlert}
            disabled={sendingTest}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 16px',
              borderRadius: '8px',
              fontSize: '12px',
              fontWeight: 700,
              cursor: 'pointer',
              background: 'var(--webcare-primary, #4f46e5)',
              color: '#ffffff',
              border: 'none',
              opacity: sendingTest ? 0.7 : 1,
            }}
          >
            {sendingTest ? <Loader2 size={14} className="webcare-spin" /> : <Send size={14} />}
            Send Test Alert Now
          </button>
        </div>

        {testResult && (
          <div style={{ marginBottom: '14px', padding: '10px 14px', borderRadius: '8px', background: testResult.success ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)', border: `1px solid ${testResult.success ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`, display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', color: testResult.success ? '#059669' : '#dc2626' }}>
            {testResult.success ? <CheckCircle2 size={16} /> : <AlertCircle size={16} />}
            {testResult.message}
          </div>
        )}

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '14px', marginBottom: '16px' }}>
          <div>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-title, #0f172a)', marginBottom: '4px' }}>
              Primary Alert Email:
            </label>
            <input
              type="email"
              value={alertEmail}
              onChange={(e) => setAlertEmail(e.target.value)}
              placeholder="admin@example.com"
              className="webcare-firewall-input"
              style={{ width: '100%', padding: '8px 12px', fontSize: '12px', borderRadius: '6px', boxSizing: 'border-box' }}
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-title, #0f172a)', marginBottom: '4px' }}>
              Slack Incoming Webhook URL:
            </label>
            <input
              type="url"
              value={slackWebhookUrl}
              onChange={(e) => setSlackWebhookUrl(e.target.value)}
              placeholder="https://hooks.slack.com/services/..."
              className="webcare-firewall-input"
              style={{ width: '100%', padding: '8px 12px', fontSize: '12px', borderRadius: '6px', boxSizing: 'border-box' }}
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-title, #0f172a)', marginBottom: '4px' }}>
              Discord Webhook URL:
            </label>
            <input
              type="url"
              value={discordWebhookUrl}
              onChange={(e) => setDiscordWebhookUrl(e.target.value)}
              placeholder="https://discord.com/api/webhooks/..."
              className="webcare-firewall-input"
              style={{ width: '100%', padding: '8px 12px', fontSize: '12px', borderRadius: '6px', boxSizing: 'border-box' }}
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--webcare-text-title, #0f172a)', marginBottom: '4px' }}>
              Custom SIEM Webhook URL:
            </label>
            <input
              type="url"
              value={customWebhookUrl}
              onChange={(e) => setCustomWebhookUrl(e.target.value)}
              placeholder="https://siem.mycompany.com/ingest"
              className="webcare-firewall-input"
              style={{ width: '100%', padding: '8px 12px', fontSize: '12px', borderRadius: '6px', boxSizing: 'border-box' }}
            />
          </div>
        </div>

        {/* Event Checkboxes */}
        <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', cursor: 'pointer', color: 'var(--webcare-text-title, #0f172a)' }}>
            <input
              type="checkbox"
              checked={alerts.notify_critical}
              onChange={(e) => setAlerts((prev: any) => ({ ...prev, notify_critical: e.target.checked }))}
              style={{ accentColor: 'var(--webcare-primary, #4f46e5)' }}
            />
            <span>Critical Malware Detections</span>
          </label>

          <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', cursor: 'pointer', color: 'var(--webcare-text-title, #0f172a)' }}>
            <input
              type="checkbox"
              checked={alerts.notify_logins}
              onChange={(e) => setAlerts((prev: any) => ({ ...prev, notify_logins: e.target.checked }))}
              style={{ accentColor: 'var(--webcare-primary, #4f46e5)' }}
            />
            <span>Admin Logins from New IPs</span>
          </label>

          <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', cursor: 'pointer', color: 'var(--webcare-text-title, #0f172a)' }}>
            <input
              type="checkbox"
              checked={alerts.notify_panic}
              onChange={(e) => setAlerts((prev: any) => ({ ...prev, notify_panic: e.target.checked }))}
              style={{ accentColor: 'var(--webcare-primary, #4f46e5)' }}
            />
            <span>L7 DDoS &amp; Panic Thresholds</span>
          </label>
        </div>
      </div>

      {/* Developer Deep Dive: AI Security Copilot */}
      <DeveloperDeepDive
        title="Developer Power-Up: AI Security Copilot (Gemini / OpenAI / Claude / Native AI)"
        badge="Optional AI Integration"
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.5 }}>
            Integrate an AI model for automatic de-obfuscation of suspicious eval/base64 code snippets and 1-click false-positive triage directly inside scan reports.
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '14px' }}>
            {/* Field 1: Latest AI Model Provider */}
            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)', marginBottom: '4px' }}>
                AI Model Provider:
              </label>
              <select
                value={aiProvider}
                onChange={(e) => handleProviderSelect(e.target.value)}
                className="webcare-input"
                style={{ width: '100%', padding: '8px 12px', fontSize: '12px', borderRadius: '6px' }}
              >
                {aiProviders.map((prov) => (
                  <option key={prov.id} value={prov.id}>
                    {prov.name} ({prov.tagline})
                  </option>
                ))}
              </select>
            </div>

            {/* Field 2: Forensic Model */}
            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)', marginBottom: '4px' }}>
                Forensic AI Model:
              </label>
              <select
                value={aiModel || currentProviderConfig.defaultModel}
                onChange={(e) => setAiModel(e.target.value)}
                className="webcare-input"
                style={{ width: '100%', padding: '8px 12px', fontSize: '12px', borderRadius: '6px' }}
              >
                {currentProviderConfig.models.map((m) => (
                  <option key={m.id} value={m.id}>
                    {m.name} — {m.desc}
                  </option>
                ))}
              </select>
            </div>

            {/* Field 3: Provider API Key */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                <label style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                  Provider API Key:
                </label>
                {currentProviderConfig.keyUrl && (
                  <a
                    href={currentProviderConfig.keyUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ fontSize: '11px', color: 'var(--webcare-primary, #4f46e5)', textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: '2px', fontWeight: 600 }}
                  >
                    Get API Key ↗
                  </a>
                )}
              </div>
              <div style={{ position: 'relative' }}>
                <input
                  type={showKey ? 'text' : 'password'}
                  value={aiApiKey}
                  onChange={(e) => setAiApiKey(e.target.value)}
                  disabled={aiProvider === 'wp_ai_connect'}
                  placeholder={currentProviderConfig.keyPlaceholder}
                  className="webcare-firewall-input"
                  style={{
                    width: '100%',
                    padding: '8px 36px 8px 12px',
                    fontSize: '12px',
                    borderRadius: '6px',
                    boxSizing: 'border-box',
                    fontFamily: 'monospace',
                    background: aiProvider === 'wp_ai_connect' ? 'var(--webcare-bg-elevated, #f1f5f9)' : undefined,
                    cursor: aiProvider === 'wp_ai_connect' ? 'not-allowed' : 'text',
                  }}
                />
                {aiProvider !== 'wp_ai_connect' && (
                  <button
                    type="button"
                    onClick={() => setShowKey(!showKey)}
                    style={{
                      position: 'absolute',
                      right: '8px',
                      top: '50%',
                      transform: 'translateY(-50%)',
                      background: 'none',
                      border: 'none',
                      cursor: 'pointer',
                      color: 'var(--webcare-text-muted, #64748b)',
                      padding: '4px',
                    }}
                    title={showKey ? 'Hide key' : 'Show key'}
                  >
                    {showKey ? <EyeOff size={14} /> : <Eye size={14} />}
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Test AI Connection Button */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap', paddingTop: '4px' }}>
            <button
              type="button"
              onClick={handleTestAiConnection}
              disabled={testingAi || (aiProvider !== 'wp_ai_connect' && !aiApiKey.trim())}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '7px 14px',
                borderRadius: '6px',
                fontSize: '12px',
                fontWeight: 700,
                cursor: 'pointer',
                background: 'var(--webcare-bg-panel, #ffffff)',
                border: '1px solid var(--webcare-border, #cbd5e1)',
                color: 'var(--webcare-text-title, #0f172a)',
                opacity: (testingAi || (aiProvider !== 'wp_ai_connect' && !aiApiKey.trim())) ? 0.6 : 1,
              }}
            >
              {testingAi ? <Loader2 size={13} className="webcare-spin" /> : <Sparkles size={13} color="var(--webcare-primary, #4f46e5)" />}
              Test AI Connection
            </button>

            {aiTestResult && (
              <div
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '6px 12px',
                  borderRadius: '6px',
                  fontSize: '11px',
                  fontWeight: 600,
                  background: aiTestResult.success ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)',
                  color: aiTestResult.success ? '#059669' : '#dc2626',
                  border: `1px solid ${aiTestResult.success ? 'rgba(16, 185, 129, 0.25)' : 'rgba(239, 68, 68, 0.25)'}`,
                }}
              >
                {aiTestResult.success ? <CheckCircle2 size={14} /> : <AlertCircle size={14} />}
                {aiTestResult.message}
              </div>
            )}
          </div>
        </div>
      </DeveloperDeepDive>
    </div>
  );
};
