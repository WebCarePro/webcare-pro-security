import React from 'react';
import {
  HardDrive,
  Cpu,
  Zap,
  Sliders,
  CheckCircle2,
  Sparkles,
  Server
} from 'lucide-react';
import { DeveloperDeepDive } from '../DeveloperDeepDive';

interface Step12Props {
  status: any;
  scanBatchSize: number;
  setScanBatchSize: (size: number) => void;
  memoryEnvelope: string;
  setMemoryEnvelope: (env: string) => void;
  adaptiveThrottling: boolean;
  setAdaptiveThrottling: (val: boolean) => void;
  batchDelayMs: number;
  setBatchDelayMs: (delay: number) => void;
  cafProfile?: string;
  setCafProfile?: (val: string) => void;
}

export const Step12ResourceEnvelope: React.FC<Step12Props> = ({
  status,
  scanBatchSize,
  setScanBatchSize,
  memoryEnvelope,
  setMemoryEnvelope,
  adaptiveThrottling,
  setAdaptiveThrottling,
  batchDelayMs,
  setBatchDelayMs,
  cafProfile,
  setCafProfile,
}) => {
  const phpMem = status?.server_info?.php?.memory_limit || '256M';

  const profiles = [
    {
      id: 'shared',
      name: 'Shared Hosting Safe',
      batch: 25,
      delay: 200,
      envelope: 'strict',
      desc: 'Optimized for cPanel and budget shared hosts to never exceed memory ceilings or trigger CPU throttling.'
    },
    {
      id: 'balanced',
      name: 'Balanced VPS / Cloud',
      batch: 50,
      delay: 50,
      envelope: 'balanced',
      desc: 'Ideal for 1-4 vCPU servers (DigitalOcean, Linode, AWS EC2, Cloudways) balancing speed and stability.'
    },
    {
      id: 'dedicated',
      name: 'Dedicated High-Throughput',
      batch: 150,
      delay: 0,
      envelope: 'performance',
      desc: 'Maximum scanning velocity for dedicated bare-metal servers and high-spec enterprise instances.'
    }
  ];

  const handleApplyProfile = (p: typeof profiles[0]) => {
    setScanBatchSize(p.batch);
    setBatchDelayMs(p.delay);
    setMemoryEnvelope(p.envelope);
  };

  return (
    <div className="webcare-wizard-step-container" style={{ display: 'flex', flexDirection: 'column', gap: '24px', width: '100%', minWidth: 0, boxSizing: 'border-box' }}>
      {/* Step Header */}
      <div>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '4px 10px', borderRadius: '20px', background: 'var(--webcare-primary-soft, rgba(79, 70, 229, 0.08))', color: 'var(--webcare-primary, #4f46e5)', fontSize: '12px', fontWeight: 700, marginBottom: '12px' }}>
          <HardDrive size={14} /> Phase 4: Scanner &amp; SOC Telemetry
        </div>
        <h1 style={{ margin: '0 0 10px 0', fontSize: '24px', fontWeight: 800, color: 'var(--webcare-text-title, #0f172a)' }}>
          Hardware Safety Envelope &amp; Adaptive Throttling
        </h1>
        <p style={{ fontSize: '14px', lineHeight: 1.6, color: 'var(--webcare-text-secondary, #475569)', margin: 0 }}>
          Prevent scanner processes from exhausting server RAM or causing checkout slowdowns during peak visitor traffic.
        </p>
      </div>

      {/* Hardware Profile Presets */}
      <div>
        <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)', marginBottom: '10px' }}>
          Recommended Hardware Tuning Profiles (Host RAM: {phpMem})
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '12px' }}>
          {profiles.map((p) => {
            const isMatch = scanBatchSize === p.batch && memoryEnvelope === p.envelope;
            return (
              <div
                key={p.id}
                onClick={() => handleApplyProfile(p)}
                style={{
                  padding: '16px',
                  borderRadius: '12px',
                  cursor: 'pointer',
                  border: isMatch ? '2px solid var(--webcare-primary, #4f46e5)' : '1px solid var(--webcare-border, #e2e8f0)',
                  background: isMatch ? 'var(--webcare-primary-soft, rgba(79, 70, 229, 0.04))' : 'var(--webcare-bg-panel, #ffffff)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '8px',
                  transition: 'all 0.15s ease'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <span style={{ fontSize: '14px', fontWeight: 700, color: isMatch ? 'var(--webcare-primary, #4f46e5)' : 'var(--webcare-text-title, #0f172a)' }}>
                    {p.name}
                  </span>
                  {isMatch && (
                    <span style={{ fontSize: '10px', fontWeight: 700, color: '#059669', background: 'rgba(16, 185, 129, 0.1)', padding: '2px 6px', borderRadius: '4px' }}>
                      ACTIVE
                    </span>
                  )}
                </div>
                <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', lineHeight: 1.4 }}>
                  {p.desc}
                </div>
                <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--webcare-text-muted, #64748b)', background: 'var(--webcare-bg-elevated, #f1f5f9)', padding: '3px 8px', borderRadius: '6px', alignSelf: 'flex-start' }}>
                  {p.batch} files / batch • {p.envelope.toUpperCase()} cap
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Adaptive Throttling Toggle */}
      <div style={{ padding: '18px 20px', borderRadius: '12px', background: 'var(--webcare-bg-elevated, #f8fafc)', border: '1px solid var(--webcare-border, #e2e8f0)' }}>
        <label style={{ display: 'flex', alignItems: 'flex-start', gap: '12px', cursor: 'pointer' }}>
          <input
            type="checkbox"
            checked={adaptiveThrottling}
            onChange={(e) => setAdaptiveThrottling(e.target.checked)}
            style={{ marginTop: '3px', accentColor: 'var(--webcare-primary, #4f46e5)' }}
          />
          <div>
            <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
              Adaptive Traffic-Aware Throttling (<code>scan_adaptive_throttling</code>)
            </div>
            <div style={{ fontSize: '12px', color: 'var(--webcare-text-secondary, #475569)', marginTop: '3px', lineHeight: 1.5 }}>
              Automatically pauses or slows background scan batches if concurrent visitor checkout traffic or server CPU load spikes. Resumes automatically when traffic normalizes.
            </div>
          </div>
        </label>
      </div>

      {/* Developer Deep Dive: Batch Size & Delay Sliders */}
      <DeveloperDeepDive
        title="Developer Controls: Fine-Grained Batch Throughput & Breathing Delay"
        badge="SettingsManager::performance"
      >
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
              <label style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                Files Per Batch (<code>scan_batch_size</code>):
              </label>
              <span style={{ fontSize: '12px', fontWeight: 800, color: 'var(--webcare-primary, #4f46e5)' }}>
                {scanBatchSize} files
              </span>
            </div>
            <input
              type="range"
              min={10}
              max={300}
              step={10}
              value={scanBatchSize}
              onChange={(e) => setScanBatchSize(parseInt(e.target.value, 10))}
              style={{ width: '100%', accentColor: 'var(--webcare-primary, #4f46e5)' }}
            />
          </div>

          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
              <label style={{ fontSize: '12px', fontWeight: 700, color: 'var(--webcare-text-title, #0f172a)' }}>
                Inter-Batch Delay (<code>scan_batch_delay_ms</code>):
              </label>
              <span style={{ fontSize: '12px', fontWeight: 800, color: 'var(--webcare-primary, #4f46e5)' }}>
                {batchDelayMs} ms
              </span>
            </div>
            <input
              type="range"
              min={0}
              max={1000}
              step={50}
              value={batchDelayMs}
              onChange={(e) => setBatchDelayMs(parseInt(e.target.value, 10))}
              style={{ width: '100%', accentColor: 'var(--webcare-primary, #4f46e5)' }}
            />
          </div>
        </div>
      </DeveloperDeepDive>
    </div>
  );
};
