import React, { useState, useRef } from 'react';
import { Download, Upload, X, CheckCircle2, AlertTriangle, FileJson, Copy, Check } from 'lucide-react';

interface BlueprintModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentConfig: any;
  onImportConfig: (importedData: any) => void;
}

export const BlueprintModal: React.FC<BlueprintModalProps> = ({
  isOpen,
  onClose,
  currentConfig,
  onImportConfig,
}) => {
  const [activeTab, setActiveTab] = useState<'export' | 'import'>('export');
  const [copied, setCopied] = useState<boolean>(false);
  const [importJsonText, setImportJsonText] = useState<string>('');
  const [importError, setImportError] = useState<string | null>(null);
  const [importSuccess, setImportSuccess] = useState<boolean>(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  if (!isOpen) return null;

  // Clean export payload (exclude raw keys by default)
  const exportPayload = {
    schema_version: '2.11.0',
    exported_at: new Date().toISOString(),
    generator: 'WebCare Pro Security Setup Studio',
    archetype: currentConfig.archetype,
    firewall_settings: currentConfig.firewall_settings,
    custom_scan_options: currentConfig.custom_scan_options,
    scan_batch_size: currentConfig.scan_batch_size,
    scan_memory_safety_envelope: currentConfig.scan_memory_safety_envelope,
    scan_adaptive_throttling: currentConfig.scan_adaptive_throttling,
    scan_batch_delay_ms: currentConfig.scan_batch_delay_ms,
    delete_data_on_uninstall: currentConfig.delete_data_on_uninstall,
    uninstall_drop_tables: currentConfig.uninstall_drop_tables,
    uninstall_delete_options: currentConfig.uninstall_delete_options,
    activity_log_settings: currentConfig.activity_log_settings,
    egress_settings: currentConfig.egress_settings,
    advanced_settings: currentConfig.advanced_settings,
    targeted_rules: currentConfig.targeted_rules,
    alerts: {
      notify_critical: currentConfig.alerts?.notify_critical,
      notify_logins: currentConfig.alerts?.notify_logins,
      notify_panic: currentConfig.alerts?.notify_panic,
    },
  };

  const jsonString = JSON.stringify(exportPayload, null, 2);

  const handleDownload = () => {
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    const dateStr = new Date().toISOString().split('T')[0];
    link.href = url;
    link.download = `webcare-blueprint-${dateStr}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(jsonString);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const text = event.target?.result as string;
        setImportJsonText(text);
        setImportError(null);
      } catch (err: any) {
        setImportError('Failed to read file: ' + err.message);
      }
    };
    reader.readAsText(file);
  };

  const handleApplyImport = () => {
    setImportError(null);
    try {
      if (!importJsonText.trim()) {
        setImportError('Please paste or upload a JSON blueprint first.');
        return;
      }
      const parsed = JSON.parse(importJsonText);
      if (!parsed || typeof parsed !== 'object') {
        throw new Error('Invalid JSON format');
      }

      onImportConfig(parsed);
      setImportSuccess(true);
      setTimeout(() => {
        setImportSuccess(false);
        onClose();
      }, 1200);
    } catch (err: any) {
      setImportError('JSON parsing error: ' + err.message);
    }
  };

  return (
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        zIndex: 999999,
        background: 'rgba(9, 13, 22, 0.75)',
        backdropFilter: 'blur(6px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '20px',
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        style={{
          width: '100%',
          maxWidth: '640px',
          background: 'var(--webcare-bg-panel, #ffffff)',
          border: '1px solid var(--webcare-border, #e2e8f0)',
          borderRadius: '20px',
          boxShadow: '0 24px 48px rgba(0, 0, 0, 0.2)',
          overflow: 'hidden',
          display: 'flex',
          flexDirection: 'column',
          maxHeight: '90vh',
        }}
      >
        {/* Modal Header */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '20px 24px',
            borderBottom: '1px solid var(--webcare-border, #e2e8f0)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div
              style={{
                width: '32px',
                height: '32px',
                borderRadius: '8px',
                background: 'rgba(79, 70, 229, 0.08)',
                color: 'var(--webcare-primary, #4f46e5)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <FileJson size={18} />
            </div>
            <div>
              <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                Agency Blueprint Manager
              </h3>
              <p style={{ margin: 0, fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)' }}>
                1-Click Export and Import for Rapid Multi-Site Fleet Deployment
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--webcare-text-muted, #64748b)',
              cursor: 'pointer',
              padding: '6px',
              borderRadius: '8px',
            }}
          >
            <X size={20} />
          </button>
        </div>

        {/* Tab Switcher */}
        <div
          style={{
            display: 'flex',
            padding: '4px',
            margin: '16px 24px 0 24px',
            background: 'var(--webcare-bg-surface, #f8fafc)',
            borderRadius: '10px',
            border: '1px solid var(--webcare-border, #e2e8f0)',
          }}
        >
          <button
            type="button"
            onClick={() => setActiveTab('export')}
            style={{
              flex: 1,
              padding: '8px 12px',
              fontSize: '12px',
              fontWeight: 700,
              borderRadius: '8px',
              border: 'none',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '6px',
              background: activeTab === 'export' ? 'var(--webcare-bg-panel, #ffffff)' : 'transparent',
              color: activeTab === 'export' ? 'var(--webcare-primary, #4f46e5)' : 'var(--webcare-text-secondary, #475569)',
              boxShadow: activeTab === 'export' ? '0 2px 4px rgba(0,0,0,0.06)' : 'none',
            }}
          >
            <Download size={14} /> Export Blueprint (.json)
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('import')}
            style={{
              flex: 1,
              padding: '8px 12px',
              fontSize: '12px',
              fontWeight: 700,
              borderRadius: '8px',
              border: 'none',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '6px',
              background: activeTab === 'import' ? 'var(--webcare-bg-panel, #ffffff)' : 'transparent',
              color: activeTab === 'import' ? 'var(--webcare-primary, #4f46e5)' : 'var(--webcare-text-secondary, #475569)',
              boxShadow: activeTab === 'import' ? '0 2px 4px rgba(0,0,0,0.06)' : 'none',
            }}
          >
            <Upload size={14} /> Import Blueprint (.json)
          </button>
        </div>

        {/* Modal Body */}
        <div style={{ padding: '20px 24px', overflowY: 'auto', flex: 1 }}>
          {activeTab === 'export' ? (
            <div>
              <p style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginBottom: '12px' }}>
                Download your current Setup Studio configuration as a portable JSON blueprint. You can import this file onto any other WordPress installation running WebCare Pro to replicate your hardened security profile.
              </p>

              <div
                style={{
                  background: 'var(--webcare-bg-surface, #f8fafc)',
                  border: '1px solid var(--webcare-border, #e2e8f0)',
                  borderRadius: '10px',
                  padding: '12px',
                  fontFamily: 'monospace',
                  fontSize: '11px',
                  color: 'var(--webcare-text-primary, #0f172a)',
                  maxHeight: '220px',
                  overflowY: 'auto',
                  whiteSpace: 'pre-wrap',
                  marginBottom: '16px',
                }}
              >
                {jsonString}
              </div>

              <div style={{ display: 'flex', gap: '10px' }}>
                <button
                  type="button"
                  onClick={handleDownload}
                  style={{
                    flex: 1,
                    padding: '10px 16px',
                    borderRadius: '10px',
                    background: 'var(--webcare-primary, #4f46e5)',
                    color: '#ffffff',
                    border: 'none',
                    fontWeight: 700,
                    fontSize: '13px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '8px',
                    cursor: 'pointer',
                  }}
                >
                  <Download size={15} /> Download `webcare-blueprint.json`
                </button>
                <button
                  type="button"
                  onClick={handleCopy}
                  style={{
                    padding: '10px 16px',
                    borderRadius: '10px',
                    background: 'var(--webcare-bg-surface, #f8fafc)',
                    color: 'var(--webcare-text-primary, #0f172a)',
                    border: '1px solid var(--webcare-border, #e2e8f0)',
                    fontWeight: 600,
                    fontSize: '13px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    cursor: 'pointer',
                  }}
                >
                  {copied ? <Check size={15} color="#10b981" /> : <Copy size={15} />}
                  {copied ? 'Copied!' : 'Copy JSON'}
                </button>
              </div>
            </div>
          ) : (
            <div>
              <p style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginBottom: '12px' }}>
                Upload or paste a previously exported WebCare Pro blueprint to apply its settings to this website.
              </p>

              {/* Upload Drop Zone */}
              <div
                onClick={() => fileInputRef.current?.click()}
                style={{
                  border: '2px dashed var(--webcare-border-strong, #cbd5e1)',
                  borderRadius: '12px',
                  padding: '24px',
                  textAlign: 'center',
                  cursor: 'pointer',
                  background: 'var(--webcare-bg-surface, #f8fafc)',
                  marginBottom: '16px',
                }}
              >
                <Upload size={28} style={{ color: 'var(--webcare-primary, #4f46e5)', margin: '0 auto 8px auto' }} />
                <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-primary, #0f172a)' }}>
                  Click to select a `.json` blueprint
                </div>
                <div style={{ fontSize: '11px', color: 'var(--webcare-text-muted, #64748b)', marginTop: '2px' }}>
                  Supports all WebCare Pro Security schema configurations
                </div>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".json,application/json"
                  style={{ display: 'none' }}
                  onChange={handleFileChange}
                />
              </div>

              {/* Paste Textarea */}
              <textarea
                rows={5}
                value={importJsonText}
                onChange={(e) => setImportJsonText(e.target.value)}
                placeholder="Or paste JSON blueprint code here..."
                style={{
                  width: '100%',
                  borderRadius: '10px',
                  border: '1px solid var(--webcare-border, #e2e8f0)',
                  background: 'var(--webcare-bg-surface, #f8fafc)',
                  color: 'var(--webcare-text-primary, #0f172a)',
                  fontFamily: 'monospace',
                  fontSize: '11px',
                  padding: '10px',
                  marginBottom: '14px',
                  boxSizing: 'border-box',
                }}
              />

              {importError && (
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    padding: '10px 12px',
                    borderRadius: '8px',
                    background: 'rgba(239, 68, 68, 0.1)',
                    border: '1px solid rgba(239, 68, 68, 0.25)',
                    color: '#ef4444',
                    fontSize: '12px',
                    marginBottom: '12px',
                  }}
                >
                  <AlertTriangle size={15} /> {importError}
                </div>
              )}

              {importSuccess && (
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    padding: '10px 12px',
                    borderRadius: '8px',
                    background: 'rgba(16, 185, 129, 0.1)',
                    border: '1px solid rgba(16, 185, 129, 0.25)',
                    color: '#10b981',
                    fontSize: '12px',
                    marginBottom: '12px',
                  }}
                >
                  <CheckCircle2 size={15} /> Blueprint successfully applied!
                </div>
              )}

              <button
                type="button"
                onClick={handleApplyImport}
                style={{
                  width: '100%',
                  padding: '10px 16px',
                  borderRadius: '10px',
                  background: 'var(--webcare-primary, #4f46e5)',
                  color: '#ffffff',
                  border: 'none',
                  fontWeight: 700,
                  fontSize: '13px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '8px',
                  cursor: 'pointer',
                }}
              >
                <CheckCircle2 size={15} /> Apply Blueprint to Setup Studio
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
