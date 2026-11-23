import React, { useState, useMemo, useEffect, useRef } from 'react';
import {
  X,
  Search,
  Command,
  Sparkles,
  Flame,
} from 'lucide-react';
import {
  NAVIGATION_CATALOG,
  NavigationItem,
  NavigationPillar,
  recordRecentNav
} from '../utils/navigationCatalog';

interface MegaMenuModalProps {
  isOpen: boolean;
  onClose: () => void;
  onNavigate: (tab: string, subTab?: string, nestedSubTab?: string) => void;
  currentTab: string;
}

const PILLAR_ORDER: NavigationPillar[] = [
  'Scanner & CVEs',
  'Firewall & Edge',
  'Login & Access',
  'Vault & Tools',
  'Settings & System'
];

export const MegaMenuModal: React.FC<MegaMenuModalProps> = ({
  isOpen,
  onClose,
  onNavigate,
  currentTab,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedPillar, setSelectedPillar] = useState<string>('all');
  const [onlyPopular, setOnlyPopular] = useState<boolean>(false);
  const searchInputRef = useRef<HTMLInputElement>(null);

  // Theme detection helper
  const [isDark, setIsDark] = useState<boolean>(() => {
    if (typeof document !== 'undefined') {
      return document.documentElement.getAttribute('data-theme') === 'dark' ||
        document.body.classList.contains('webcare-theme-dark');
    }
    return false;
  });

  useEffect(() => {
    const checkTheme = () => {
      const dark = document.documentElement.getAttribute('data-theme') === 'dark' ||
        document.body.classList.contains('webcare-theme-dark');
      setIsDark(dark);
    };
    checkTheme();
    const observer = new MutationObserver(checkTheme);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    observer.observe(document.body, { attributes: true, attributeFilter: ['class'] });
    return () => observer.disconnect();
  }, []);

  // Category theme styling metadata for the 5 Pillars
  const pillarStyles: Record<NavigationPillar, {
    primary: string;
    softBg: string;
    border: string;
    accent: string;
    iconBg: string;
    iconColor: string;
  }> = useMemo(() => {
    if (isDark) {
      return {
        'Scanner & CVEs': {
          primary: '#38bdf8',
          softBg: 'rgba(2, 132, 199, 0.08)',
          border: 'rgba(56, 189, 248, 0.25)',
          accent: '#38bdf8',
          iconBg: 'rgba(56, 189, 248, 0.16)',
          iconColor: '#38bdf8',
        },
        'Firewall & Edge': {
          primary: '#f87171',
          softBg: 'rgba(239, 68, 68, 0.08)',
          border: 'rgba(248, 113, 113, 0.25)',
          accent: '#f87171',
          iconBg: 'rgba(239, 68, 68, 0.16)',
          iconColor: '#f87171',
        },
        'Login & 2FA': {
          primary: '#34d399',
          softBg: 'rgba(16, 185, 129, 0.08)',
          border: 'rgba(52, 211, 153, 0.25)',
          accent: '#34d399',
          iconBg: 'rgba(16, 185, 129, 0.16)',
          iconColor: '#34d399',
        },
        'Vault & Forensics': {
          primary: '#818cf8',
          softBg: 'rgba(99, 102, 241, 0.08)',
          border: 'rgba(129, 140, 248, 0.25)',
          accent: '#818cf8',
          iconBg: 'rgba(99, 102, 241, 0.16)',
          iconColor: '#818cf8',
        },
        'Settings & System': {
          primary: '#94a3b8',
          softBg: 'rgba(148, 163, 184, 0.08)',
          border: 'rgba(148, 163, 184, 0.25)',
          accent: '#94a3b8',
          iconBg: 'rgba(148, 163, 184, 0.16)',
          iconColor: '#94a3b8',
        },
      };
    }

    return {
      'Scanner & CVEs': {
        primary: '#0284c7',
        softBg: 'rgba(2, 132, 199, 0.05)',
        border: 'rgba(2, 132, 199, 0.22)',
        accent: '#0284c7',
        iconBg: 'rgba(2, 132, 199, 0.12)',
        iconColor: '#0284c7',
      },
      'Firewall & Edge': {
        primary: '#dc2626',
        softBg: 'rgba(220, 38, 38, 0.04)',
        border: 'rgba(220, 38, 38, 0.22)',
        accent: '#dc2626',
        iconBg: 'rgba(220, 38, 38, 0.12)',
        iconColor: '#dc2626',
      },
      'Login & 2FA': {
        primary: '#059669',
        softBg: 'rgba(5, 150, 105, 0.05)',
        border: 'rgba(5, 150, 105, 0.22)',
        accent: '#059669',
        iconBg: 'rgba(5, 150, 105, 0.12)',
        iconColor: '#059669',
      },
      'Vault & Forensics': {
        primary: '#4f46e5',
        softBg: 'rgba(79, 70, 229, 0.05)',
        border: 'rgba(79, 70, 229, 0.22)',
        accent: '#4f46e5',
        iconBg: 'rgba(79, 70, 229, 0.12)',
        iconColor: '#4f46e5',
      },
      'Settings & System': {
        primary: '#475569',
        softBg: 'rgba(71, 85, 105, 0.05)',
        border: 'rgba(71, 85, 105, 0.22)',
        accent: '#475569',
        iconBg: 'rgba(71, 85, 105, 0.12)',
        iconColor: '#475569',
      },
    };
  }, [isDark]);

  // Quick Task Shortcuts for 1-click discovery
  const quickShortcuts = useMemo(() => [
    { label: 'Unban IP', query: 'unban' },
    { label: '15-Min Safe Mode', query: 'safe mode' },
    { label: 'Cloudflare Sync', query: 'cloudflare' },
    { label: 'Passkeys & 2FA', query: 'passkey' },
    { label: 'Database Backup', query: 'backup' },
    { label: 'Panic Lockdown', query: 'lockdown' },
  ], []);

  // Filter items based on search term, selected pillar, and popular filter
  const filteredModulesWithScores = useMemo(() => {
    let baseList = NAVIGATION_CATALOG;

    if (onlyPopular) {
      baseList = baseList.filter((m) => m.isPopular);
    }

    if (selectedPillar !== 'all') {
      baseList = baseList.filter((m) => m.pillar === selectedPillar);
    }

    const raw = searchTerm.trim().toLowerCase();
    if (!raw) {
      return baseList.map((m) => ({ item: m, score: 100, matchReason: '' }));
    }

    const stopWords = new Set(['how', 'to', 'do', 'i', 'where', 'can', 'find', 'the', 'a', 'an', 'in', 'of', 'for', 'on', 'my', 'is', 'want', 'please']);
    const rawTokens = raw.replace(/[^a-z0-9\s_-]/g, ' ').split(/\s+/).filter(Boolean);
    const meaningfulTokens = rawTokens.filter((t) => !stopWords.has(t));
    const queryTokens = meaningfulTokens.length > 0 ? meaningfulTokens : rawTokens;

    const scored: Array<{ item: NavigationItem; score: number; matchReason: string }> = [];

    for (const m of baseList) {
      let score = 0;
      let reason = '';

      const titleLower = m.title.toLowerCase();
      const descLower = m.desc.toLowerCase();
      const pillarLower = m.pillar.toLowerCase();
      const keywordsLower = m.keywords.map((k) => k.toLowerCase());
      const intentsLower = (m.intents || []).map((i) => i.toLowerCase());

      if (titleLower.includes(raw)) {
        score += 120;
        reason = `Title: "${m.title}"`;
      }

      for (const intent of intentsLower) {
        if (intent.includes(raw)) {
          score += 100;
          if (!reason) reason = `Intent: "${intent}"`;
          break;
        }
        for (const t of queryTokens) {
          if (intent.includes(t)) {
            score += 35;
            if (!reason) reason = `Intent: "${intent}"`;
          }
        }
      }

      for (const kw of keywordsLower) {
        if (kw === raw || raw.includes(kw)) {
          score += 80;
          if (!reason) reason = `Keyword: "${kw}"`;
        } else {
          for (const t of queryTokens) {
            if (kw.includes(t)) {
              score += 25;
              if (!reason) reason = `Keyword: "${kw}"`;
            }
          }
        }
      }

      if (descLower.includes(raw)) {
        score += 45;
        if (!reason) reason = 'Description match';
      }

      if (pillarLower.includes(raw)) {
        score += 20;
      }

      if (score > 0) {
        scored.push({ item: m, score, matchReason: reason });
      }
    }

    return scored.sort((a, b) => b.score - a.score);
  }, [searchTerm, selectedPillar, onlyPopular]);

  const filteredModules = useMemo(() => {
    return filteredModulesWithScores.map((s) => s.item);
  }, [filteredModulesWithScores]);

  // Group filtered modules by the 5 Pillars (preserving PILLAR_ORDER)
  const pillarsGrouped = useMemo(() => {
    const map = new Map<NavigationPillar, Array<{ item: NavigationItem; matchReason: string }>>();
    for (const p of PILLAR_ORDER) {
      map.set(p, []);
    }

    for (const scored of filteredModulesWithScores) {
      const p = scored.item.pillar;
      if (!map.has(p)) {
        map.set(p, []);
      }
      map.get(p)!.push({ item: scored.item, matchReason: scored.matchReason });
    }

    // Return only pillars that have at least 1 item matching current filters
    return Array.from(map.entries()).filter(([_, items]) => items.length > 0);
  }, [filteredModulesWithScores]);

  // Focus search input when opened
  useEffect(() => {
    if (isOpen) {
      setSearchTerm('');
      setSelectedPillar('all');
      setOnlyPopular(false);
      setTimeout(() => {
        searchInputRef.current?.focus();
      }, 50);
    }
  }, [isOpen]);

  // Keyboard shortcut: Escape to close
  useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  const handleNavigateItem = (item: NavigationItem) => {
    recordRecentNav(item.id);
    onNavigate(item.slug, item.tab, item.subtab || item.nestedSubTab);
    onClose();
  };

  if (!isOpen) return null;

  return (
    <div
      className="webcare-mega-menu-overlay"
      onClick={onClose}
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        zIndex: 999999,
        background: 'rgba(15, 23, 42, 0.65)',
        backdropFilter: 'blur(6px)',
        display: 'flex',
        alignItems: 'flex-start',
        justifyContent: 'center',
        padding: '24px 16px',
        overflowY: 'auto',
      }}
    >
      <div
        className="webcare-mega-menu-container"
        onClick={(e) => e.stopPropagation()}
        style={{
          width: '100%',
          maxWidth: '1240px',
          background: 'var(--webcare-bg-panel, #ffffff)',
          border: '1px solid var(--webcare-border-std, #e2e8f0)',
          borderRadius: '16px',
          boxShadow: '0 20px 45px -10px rgba(0, 0, 0, 0.35)',
          overflow: 'hidden',
          animation: 'webcareModalIn 0.18s ease-out',
        }}
      >
        {/* Header Bar */}
        <div
          style={{
            padding: '16px 22px',
            borderBottom: '1px solid var(--webcare-border-std, #e2e8f0)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '16px',
            background: 'var(--webcare-bg-surface, #f8fafc)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div
              style={{
                width: '36px',
                height: '36px',
                borderRadius: '8px',
                background: 'linear-gradient(135deg, #4f46e5 0%, #4338ca 100%)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#ffffff',
                boxShadow: '0 4px 12px rgba(79, 70, 229, 0.25)',
              }}
            >
              <Command size={18} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <h2
                  style={{
                    margin: 0,
                    fontSize: '17px',
                    fontWeight: 700,
                    color: 'var(--webcare-text-primary, #0f172a)',
                    letterSpacing: '-0.2px',
                  }}
                >
                  All Security Modules (74 Tools &amp; Actions)
                </h2>
                <span
                  style={{
                    fontSize: '11.5px',
                    fontWeight: 800,
                    padding: '3px 10px',
                    borderRadius: '12px',
                    background: isDark ? 'rgba(99, 102, 241, 0.28)' : 'rgba(79, 70, 229, 0.1)',
                    color: isDark ? '#c7d2fe' : '#4f46e5',
                    border: isDark ? '1px solid #818cf8' : '1px solid rgba(79, 70, 229, 0.25)',
                    letterSpacing: '0.3px',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '5px',
                  }}
                >
                  <span
                    style={{
                      width: '6px',
                      height: '6px',
                      borderRadius: '50%',
                      background: isDark ? '#818cf8' : '#4f46e5',
                    }}
                  />
                  <span>5 Pillars • {NAVIGATION_CATALOG.length} Modules</span>
                </span>
              </div>
              <p
                style={{
                  margin: '2px 0 0 0',
                  fontSize: '12px',
                  color: 'var(--webcare-text-muted, #64748b)',
                }}
              >
                Instant unified catalog across Scanner, Firewall, Login, Vault, and Settings
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="webcare-mega-menu-close"
            style={{
              background: 'transparent',
              border: 'none',
              cursor: 'pointer',
              color: 'var(--webcare-text-muted, #64748b)',
              padding: '6px',
              borderRadius: '6px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              transition: 'all 0.15s ease',
            }}
            aria-label="Close Command Center"
          >
            <X size={20} />
          </button>
        </div>

        {/* Search Bar & Category Filter Pills */}
        <div
          style={{
            padding: '14px 22px',
            borderBottom: '1px solid var(--webcare-border-std, #e2e8f0)',
            background: 'var(--webcare-bg-panel, #ffffff)',
            display: 'flex',
            flexDirection: 'column',
            gap: '12px',
          }}
        >
          <div
            style={{
              position: 'relative',
              display: 'flex',
              alignItems: 'center',
            }}
          >
            <Search
              size={18}
              style={{
                position: 'absolute',
                left: '14px',
                color: 'var(--webcare-text-muted, #64748b)',
                pointerEvents: 'none',
              }}
            />
            <input
              ref={searchInputRef}
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search across all 74 modules by name, task, or question (e.g. unban, whitelist, 2fa, cloudflare, safe mode)..."
              style={{
                width: '100%',
                padding: '11px 14px 11px 42px',
                borderRadius: '10px',
                border: isDark ? '1px solid rgba(255, 255, 255, 0.2)' : '1px solid var(--webcare-border-form, #cbd5e1)',
                background: isDark ? 'rgba(15, 23, 42, 0.85)' : 'var(--webcare-bg-surface, #f8fafc)',
                color: isDark ? '#ffffff' : 'var(--webcare-text-primary, #0f172a)',
                fontSize: '14px',
                outline: 'none',
                transition: 'border-color 0.15s ease, box-shadow 0.15s ease',
              }}
              onFocus={(e) => {
                e.currentTarget.style.borderColor = isDark ? '#818cf8' : '#4f46e5';
                e.currentTarget.style.boxShadow = isDark ? '0 0 10px rgba(129, 140, 248, 0.35)' : '0 0 0 3px rgba(79, 70, 229, 0.15)';
              }}
              onBlur={(e) => {
                e.currentTarget.style.borderColor = isDark ? 'rgba(255, 255, 255, 0.2)' : 'var(--webcare-border-form, #cbd5e1)';
                e.currentTarget.style.boxShadow = 'none';
              }}
            />
            {searchTerm && (
              <button
                type="button"
                onClick={() => setSearchTerm('')}
                style={{
                  position: 'absolute',
                  right: '12px',
                  background: 'transparent',
                  border: 'none',
                  cursor: 'pointer',
                  color: 'var(--webcare-text-muted, #64748b)',
                  padding: '4px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <X size={16} />
              </button>
            )}
          </div>

          {/* Quick Task Shortcuts Bar */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              overflowX: 'auto',
              paddingBottom: '2px',
            }}
          >
            <span style={{ fontSize: '11px', fontWeight: 700, color: 'var(--webcare-text-muted, #64748b)', whiteSpace: 'nowrap', display: 'flex', alignItems: 'center', gap: '4px' }}>
              <Sparkles size={12} color="#0284c7" /> Quick Shortcuts:
            </span>
            {quickShortcuts.map((qs) => (
              <button
                key={qs.label}
                type="button"
                onClick={() => setSearchTerm(qs.query)}
                style={{
                  padding: '3px 9px',
                  borderRadius: '6px',
                  fontSize: '11px',
                  fontWeight: 600,
                  whiteSpace: 'nowrap',
                  cursor: 'pointer',
                  border: isDark ? '1px solid rgba(255, 255, 255, 0.1)' : '1px solid #e2e8f0',
                  background: isDark ? 'rgba(30, 41, 59, 0.7)' : '#f1f5f9',
                  color: isDark ? '#cbd5e1' : '#334155',
                  transition: 'all 0.15s ease',
                }}
              >
                {qs.label}
              </button>
            ))}
          </div>

          {/* 5 Matching Pillars Filter Bar + Popular Filter Chip */}
          <div
            className="webcare-mega-filter-bar"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              overflowX: 'auto',
              paddingBottom: '6px',
            }}
          >
            {/* All Modules Pill */}
            <button
              type="button"
              onClick={() => { setSelectedPillar('all'); setOnlyPopular(false); }}
              style={{
                padding: '6px 13px',
                borderRadius: '20px',
                fontSize: '12px',
                fontWeight: selectedPillar === 'all' && !onlyPopular ? 700 : 600,
                whiteSpace: 'nowrap',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
                border: selectedPillar === 'all' && !onlyPopular
                  ? (isDark ? '1px solid #818cf8' : '1px solid #4f46e5')
                  : (isDark ? '1px solid rgba(255, 255, 255, 0.28)' : '1px solid var(--webcare-border-std, #e2e8f0)'),
                background: selectedPillar === 'all' && !onlyPopular
                  ? (isDark ? 'linear-gradient(135deg, #4f46e5 0%, #6366f1 100%)' : '#4f46e5')
                  : (isDark ? '#1e293b' : 'var(--webcare-bg-surface, #f8fafc)'),
                color: selectedPillar === 'all' && !onlyPopular
                  ? '#ffffff'
                  : (isDark ? '#f8fafc' : 'var(--webcare-text-secondary, #475569)'),
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
              }}
            >
              <span>All Modules</span>
              <span
                style={{
                  fontSize: '10px',
                  padding: '1.5px 6.5px',
                  borderRadius: '10px',
                  background: selectedPillar === 'all' && !onlyPopular
                    ? 'rgba(255, 255, 255, 0.25)'
                    : (isDark ? 'rgba(129, 140, 248, 0.2)' : 'var(--webcare-border-std, #e2e8f0)'),
                  color: selectedPillar === 'all' && !onlyPopular
                    ? '#ffffff'
                    : (isDark ? '#c7d2fe' : 'var(--webcare-text-muted, #64748b)'),
                  fontWeight: 800,
                }}
              >
                {NAVIGATION_CATALOG.length}
              </span>
            </button>

            {/* Popular Filter Chip */}
            <button
              type="button"
              onClick={() => { setOnlyPopular(!onlyPopular); setSelectedPillar('all'); }}
              style={{
                padding: '6px 13px',
                borderRadius: '20px',
                fontSize: '12px',
                fontWeight: onlyPopular ? 700 : 600,
                whiteSpace: 'nowrap',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
                border: onlyPopular
                  ? '1px solid #f59e0b'
                  : (isDark ? '1px solid rgba(255, 255, 255, 0.28)' : '1px solid var(--webcare-border-std, #e2e8f0)'),
                background: onlyPopular
                  ? (isDark ? 'rgba(245, 158, 11, 0.22)' : '#fffbeb')
                  : (isDark ? '#1e293b' : 'var(--webcare-bg-surface, #f8fafc)'),
                color: onlyPopular
                  ? (isDark ? '#fbbf24' : '#b45309')
                  : (isDark ? '#f8fafc' : 'var(--webcare-text-secondary, #475569)'),
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
              }}
            >
              <Flame size={13} color={onlyPopular ? '#f59e0b' : '#94a3b8'} />
              <span>Popular (8 Core Tools)</span>
            </button>

            {/* 5 Standard Pillars */}
            {PILLAR_ORDER.map((pillar) => {
              const isSelected = selectedPillar === pillar && !onlyPopular;
              const count = NAVIGATION_CATALOG.filter((m) => m.pillar === pillar).length;

              return (
                <button
                  key={pillar}
                  type="button"
                  onClick={() => { setSelectedPillar(pillar); setOnlyPopular(false); }}
                  style={{
                    padding: '6px 13px',
                    borderRadius: '20px',
                    fontSize: '12px',
                    fontWeight: isSelected ? 700 : 600,
                    whiteSpace: 'nowrap',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                    border: isSelected
                      ? (isDark ? '1px solid #818cf8' : '1px solid #4f46e5')
                      : (isDark ? '1px solid rgba(255, 255, 255, 0.28)' : '1px solid var(--webcare-border-std, #e2e8f0)'),
                    background: isSelected
                      ? (isDark ? 'linear-gradient(135deg, #4f46e5 0%, #6366f1 100%)' : '#4f46e5')
                      : (isDark ? '#1e293b' : 'var(--webcare-bg-surface, #f8fafc)'),
                    color: isSelected
                      ? '#ffffff'
                      : (isDark ? '#f8fafc' : 'var(--webcare-text-secondary, #475569)'),
                    display: 'flex',
                    alignItems: 'center',
                    gap: '7px',
                  }}
                >
                  <span>{pillar}</span>
                  <span
                    style={{
                      fontSize: '10px',
                      padding: '1.5px 6.5px',
                      borderRadius: '10px',
                      background: isSelected
                        ? 'rgba(255, 255, 255, 0.25)'
                        : (isDark ? 'rgba(129, 140, 248, 0.2)' : 'var(--webcare-border-std, #e2e8f0)'),
                      color: isSelected
                        ? '#ffffff'
                        : (isDark ? '#c7d2fe' : 'var(--webcare-text-muted, #64748b)'),
                      fontWeight: 800,
                    }}
                  >
                    {count}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Modules Grid categorized into 5 Pillars */}
        <div
          style={{
            padding: '20px 22px',
            maxHeight: 'calc(80vh - 190px)',
            overflowY: 'auto',
          }}
        >
          {filteredModules.length === 0 ? (
            <div
              style={{
                textAlign: 'center',
                padding: '48px 20px',
                color: 'var(--webcare-text-muted, #64748b)',
              }}
            >
              <Search size={32} style={{ margin: '0 auto 12px auto', opacity: 0.4 }} />
              <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>
                No security modules found matching "{searchTerm}"
              </div>
              <p style={{ fontSize: '12px', marginTop: '4px' }}>
                Try searching for terms like "unban", "firewall", "2fa", "cve", "backup", or "rules"
              </p>
            </div>
          ) : (
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))',
                gap: '18px',
              }}
            >
              {pillarsGrouped.map(([pillarTitle, pillarItems]) => {
                const styleMeta = pillarStyles[pillarTitle] || {
                  primary: '#4f46e5',
                  softBg: 'rgba(79, 70, 229, 0.04)',
                  border: 'rgba(79, 70, 229, 0.2)',
                  accent: '#4f46e5',
                  iconBg: 'rgba(79, 70, 229, 0.1)',
                  iconColor: '#4f46e5',
                };

                return (
                  <div
                    key={pillarTitle}
                    style={{
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '8px',
                      background: styleMeta.softBg,
                      border: `1px solid ${styleMeta.border}`,
                      borderRadius: '12px',
                      padding: '12px 14px',
                      transition: 'border-color 0.2s ease',
                    }}
                  >
                    <div
                      style={{
                        fontSize: '11px',
                        fontWeight: 800,
                        textTransform: 'uppercase',
                        letterSpacing: '0.6px',
                        color: styleMeta.primary,
                        padding: '2px 4px 8px 4px',
                        borderBottom: `1px solid ${styleMeta.border}`,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                      }}
                    >
                      <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: styleMeta.primary }} />
                        <span>{pillarTitle}</span>
                      </span>
                      <span
                        style={{
                          fontSize: '10px',
                          padding: '1.5px 7px',
                          borderRadius: '10px',
                          background: isDark ? 'rgba(15, 23, 42, 0.75)' : 'var(--webcare-bg-panel, #ffffff)',
                          color: isDark ? '#f8fafc' : styleMeta.primary,
                          border: isDark ? `1px solid ${styleMeta.primary}` : `1px solid ${styleMeta.border}`,
                          fontWeight: 800,
                        }}
                      >
                        {pillarItems.length}
                      </span>
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                      {pillarItems.map(({ item, matchReason }) => {
                        const IconComp = item.icon;
                        const isItemActive = currentTab === item.tab || currentTab === item.slug;

                        return (
                          <button
                            key={item.id}
                            type="button"
                            onClick={() => handleNavigateItem(item)}
                            className="webcare-mega-menu-item"
                            style={{
                              textAlign: 'left',
                              display: 'flex',
                              alignItems: 'flex-start',
                              gap: '12px',
                              padding: '9px 12px',
                              borderRadius: '8px',
                              border: isItemActive ? `1px solid ${styleMeta.primary}` : '1px solid transparent',
                              background: isItemActive ? 'var(--webcare-bg-panel, #ffffff)' : 'transparent',
                              boxShadow: isItemActive ? '0 2px 8px rgba(0,0,0,0.06)' : 'none',
                              cursor: 'pointer',
                              transition: 'all 0.15s ease',
                              width: '100%',
                            }}
                          >
                            <div
                              style={{
                                width: '30px',
                                height: '30px',
                                borderRadius: '7px',
                                background: isItemActive ? styleMeta.primary : styleMeta.iconBg,
                                color: isItemActive ? '#ffffff' : styleMeta.iconColor,
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'center',
                                flexShrink: 0,
                                marginTop: '2px',
                                transition: 'all 0.15s ease',
                              }}
                            >
                              <IconComp size={16} />
                            </div>

                            <div style={{ flex: 1, minWidth: 0 }}>
                              <div
                                style={{
                                  display: 'flex',
                                  alignItems: 'center',
                                  justifyContent: 'space-between',
                                  gap: '6px',
                                }}
                              >
                                <span
                                  style={{
                                    fontSize: '13px',
                                    fontWeight: 700,
                                    color: isItemActive ? styleMeta.primary : 'var(--webcare-text-primary, #0f172a)',
                                    whiteSpace: 'nowrap',
                                    overflow: 'hidden',
                                    textOverflow: 'ellipsis',
                                  }}
                                >
                                  {item.title}
                                </span>

                                <div style={{ display: 'flex', alignItems: 'center', gap: '4px', flexShrink: 0 }}>
                                  {item.isAdvanced && (
                                    <span
                                      style={{
                                        fontSize: '9px',
                                        fontWeight: 800,
                                        padding: '1px 5px',
                                        borderRadius: '4px',
                                        background: 'rgba(99, 102, 241, 0.12)',
                                        color: '#6366f1'
                                      }}
                                    >
                                      DEV
                                    </span>
                                  )}
                                  {item.badge && (
                                    <span
                                      className={`webcare-badge-pill webcare-badge-${item.badgeType || 'info'}`}
                                      style={{ fontSize: '9px', padding: '1px 6px' }}
                                    >
                                      {item.badge}
                                    </span>
                                  )}
                                </div>
                              </div>

                              <div
                                style={{
                                  fontSize: '11px',
                                  color: 'var(--webcare-text-muted, #64748b)',
                                  lineHeight: '1.4',
                                  marginTop: '2px',
                                  display: '-webkit-box',
                                  WebkitLineClamp: 2,
                                  WebkitBoxOrient: 'vertical',
                                  overflow: 'hidden',
                                }}
                              >
                                {item.desc}
                              </div>

                              {searchTerm && matchReason && (
                                <div
                                  style={{
                                    marginTop: '4px',
                                    display: 'inline-flex',
                                    alignItems: 'center',
                                    gap: '4px',
                                    padding: '2px 6px',
                                    borderRadius: '4px',
                                    fontSize: '10px',
                                    fontWeight: 700,
                                    background: isDark ? 'rgba(56, 189, 248, 0.12)' : 'rgba(2, 132, 199, 0.08)',
                                    color: isDark ? '#38bdf8' : '#0284c7',
                                    border: isDark ? '1px solid rgba(56, 189, 248, 0.25)' : '1px solid rgba(2, 132, 199, 0.2)',
                                  }}
                                >
                                  <span>🎯 {matchReason}</span>
                                </div>
                              )}
                            </div>
                          </button>
                        );
                      })}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Footer Bar with Keyboard Helper */}
        <div
          style={{
            padding: '12px 24px',
            borderTop: '1px solid var(--webcare-border-std, #e2e8f0)',
            background: 'var(--webcare-bg-surface, #f8fafc)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            fontSize: '12px',
            color: 'var(--webcare-text-muted, #64748b)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <span>
              <kbd
                style={{
                  background: 'var(--webcare-bg-panel, #ffffff)',
                  border: '1px solid var(--webcare-border-form, #cbd5e1)',
                  borderRadius: '4px',
                  padding: '2px 5px',
                  fontSize: '11px',
                  fontWeight: 600,
                }}
              >
                Esc
              </kbd>{' '}
              to close
            </span>
            <span>
              <kbd
                style={{
                  background: 'var(--webcare-bg-panel, #ffffff)',
                  border: '1px solid var(--webcare-border-form, #cbd5e1)',
                  borderRadius: '4px',
                  padding: '2px 5px',
                  fontSize: '11px',
                  fontWeight: 600,
                }}
              >
                Ctrl + K
              </kbd>{' '}
              quick-jump search
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#10b981' }} />
            <span>5 Core Pillars • 74 Modules</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default MegaMenuModal;
