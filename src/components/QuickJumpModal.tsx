import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  Search,
  ArrowRight,
  Clock,
  ExternalLink,
  Sparkles,
} from 'lucide-react';
import {
  NAVIGATION_CATALOG,
  NavigationItem,
  getRecentNavItems,
  recordRecentNav
} from '../utils/navigationCatalog';

interface QuickJumpModalProps {
  isOpen: boolean;
  onClose: () => void;
  onNavigate: (slug: string, tab?: string, section?: string) => void;
  onSwitchToAdvancedMode?: () => void;
}

export const QuickJumpModal: React.FC<QuickJumpModalProps> = ({
  isOpen,
  onClose,
  onNavigate,
  onSwitchToAdvancedMode
}) => {
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [recentItems, setRecentItems] = useState<NavigationItem[]>([]);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (isOpen) {
      setQuery('');
      setSelectedIndex(0);
      setRecentItems(getRecentNavItems());
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [isOpen]);

  const filteredItems = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) {
      return NAVIGATION_CATALOG;
    }
    return NAVIGATION_CATALOG.filter((item) => {
      const inTitle = item.title.toLowerCase().includes(q);
      const inDesc = item.desc.toLowerCase().includes(q);
      const inKeywords = item.keywords.some((k) => k.toLowerCase().includes(q));
      const inPillar = item.pillar.toLowerCase().includes(q);
      const inIntents = (item.intents || []).some((intent) => intent.toLowerCase().includes(q));
      return inTitle || inDesc || inKeywords || inPillar || inIntents;
    });
  }, [query]);

  // Keep selected index in bounds
  useEffect(() => {
    if (selectedIndex >= filteredItems.length) {
      setSelectedIndex(Math.max(0, filteredItems.length - 1));
    }
  }, [filteredItems.length, selectedIndex]);

  const handleSelect = (item: NavigationItem) => {
    recordRecentNav(item.id);
    if (item.isAdvanced && onSwitchToAdvancedMode) {
      onSwitchToAdvancedMode();
    }
    onNavigate(item.slug, item.tab, item.section || item.subtab);
    onClose();
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex((prev) => (prev < filteredItems.length - 1 ? prev + 1 : 0));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex((prev) => (prev > 0 ? prev - 1 : filteredItems.length - 1));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (filteredItems[selectedIndex]) {
        handleSelect(filteredItems[selectedIndex]);
      }
    } else if (e.key === 'Escape') {
      e.preventDefault();
      onClose();
    }
  };

  if (!isOpen) return null;

  return (
    <div
      className="webcare-modal-backdrop"
      onClick={onClose}
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(15, 23, 42, 0.65)',
        backdropFilter: 'blur(4px)',
        zIndex: 99999,
        display: 'flex',
        alignItems: 'flex-start',
        justifyContent: 'center',
        paddingTop: '8vh'
      }}
    >
      <div
        className="webcare-quickjump-box"
        onClick={(e) => e.stopPropagation()}
        style={{
          width: '100%',
          maxWidth: '620px',
          background: 'var(--webcare-bg-card, #ffffff)',
          borderRadius: '14px',
          boxShadow: '0 25px 30px -5px rgba(0, 0, 0, 0.25), 0 12px 16px -6px rgba(0, 0, 0, 0.15)',
          border: '1px solid var(--webcare-border, #e2e8f0)',
          overflow: 'hidden',
          display: 'flex',
          flexDirection: 'column',
          maxHeight: '78vh',
          animation: 'webcare-fade-in 0.15s ease-out'
        }}
      >
        {/* Search Input Bar */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            padding: '14px 18px',
            borderBottom: '1px solid var(--webcare-border, #e2e8f0)',
            background: 'var(--webcare-bg-surface, #f8fafc)'
          }}
        >
          <Search size={18} color="#6366f1" style={{ flexShrink: 0 }} />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setSelectedIndex(0);
            }}
            onKeyDown={handleKeyDown}
            placeholder="Search all 74 modules, tasks & shortcuts (e.g. unban, whitelist, 2fa, cloudflare)..."
            style={{
              width: '100%',
              border: 'none',
              background: 'transparent',
              outline: 'none',
              fontSize: '14px',
              fontWeight: 500,
              color: 'var(--webcare-text-primary, #0f172a)'
            }}
          />
          <kbd
            style={{
              background: 'var(--webcare-bg-deep, #e2e8f0)',
              border: '1px solid var(--webcare-border, #cbd5e1)',
              borderRadius: '4px',
              padding: '2px 6px',
              fontSize: '11px',
              color: 'var(--webcare-text-muted, #64748b)',
              fontWeight: 600
            }}
          >
            ESC
          </kbd>
        </div>

        {/* Recently Visited Strip (Shown when query is empty) */}
        {!query.trim() && recentItems.length > 0 && (
          <div
            style={{
              padding: '10px 16px 8px',
              borderBottom: '1px solid var(--webcare-border, #e2e8f0)',
              background: 'var(--webcare-bg-surface-elevated, #f1f5f9)',
              display: 'flex',
              flexDirection: 'column',
              gap: '6px'
            }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                fontSize: '11px',
                fontWeight: 700,
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
                color: 'var(--webcare-text-muted, #64748b)'
              }}
            >
              <Clock size={12} />
              <span>Recently Visited</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              {recentItems.map((item) => {
                const IconComponent = item.icon;
                return (
                  <button
                    key={`recent-${item.id}`}
                    type="button"
                    onClick={() => handleSelect(item)}
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '6px',
                      padding: '4px 10px',
                      borderRadius: '6px',
                      fontSize: '11.5px',
                      fontWeight: 600,
                      background: 'var(--webcare-bg-card, #ffffff)',
                      border: '1px solid var(--webcare-border, #cbd5e1)',
                      color: 'var(--webcare-text-primary, #0f172a)',
                      cursor: 'pointer',
                      transition: 'all 0.15s ease'
                    }}
                  >
                    <IconComponent size={12} color="#6366f1" />
                    <span>{item.title}</span>
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {/* Results List */}
        <div
          ref={listRef}
          style={{
            overflowY: 'auto',
            padding: '8px',
            flex: 1
          }}
        >
          {filteredItems.length === 0 ? (
            <div style={{ padding: '36px 16px', textAlign: 'center', color: 'var(--webcare-text-muted, #64748b)' }}>
              <p style={{ margin: '0 0 6px 0', fontSize: '14px', fontWeight: 600 }}>No matching tools or tasks found</p>
              <p style={{ margin: 0, fontSize: '12px' }}>
                Try searching with synonyms like <em>unban</em>, <em>safe mode</em>, <em>whitelist</em>, <em>cloudflare</em>, or <em>passkey</em>.
              </p>
            </div>
          ) : (
            filteredItems.map((item, idx) => {
              const isSelected = idx === selectedIndex;
              const IconComponent = item.icon;
              return (
                <div
                  key={item.id}
                  onClick={() => handleSelect(item)}
                  onMouseEnter={() => setSelectedIndex(idx)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '10px 14px',
                    borderRadius: '8px',
                    cursor: 'pointer',
                    background: isSelected ? 'var(--webcare-bg-surface-hover, #f1f5f9)' : 'transparent',
                    border: isSelected ? '1px solid var(--webcare-border-strong, #cbd5e1)' : '1px solid transparent',
                    transition: 'all 0.1s ease',
                    marginBottom: '4px'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px', minWidth: 0 }}>
                    <div
                      style={{
                        width: '34px',
                        height: '34px',
                        borderRadius: '8px',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        background: isSelected ? 'rgba(79, 70, 229, 0.14)' : 'var(--webcare-bg-surface, #f8fafc)',
                        color: isSelected ? '#4f46e5' : 'var(--webcare-text-muted, #64748b)',
                        border: '1px solid var(--webcare-border, #e2e8f0)',
                        flexShrink: 0
                      }}
                    >
                      <IconComponent size={16} />
                    </div>

                    <div style={{ minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--webcare-text-primary, #0f172a)' }}>
                          {item.title}
                        </span>
                        {item.badge && (
                          <span
                            className={`webcare-badge-pill webcare-badge-${item.badgeType || 'info'}`}
                            style={{ fontSize: '9.5px', padding: '1px 6px' }}
                          >
                            {item.badge}
                          </span>
                        )}
                        {item.isAdvanced && (
                          <span
                            style={{
                              fontSize: '10px',
                              fontWeight: 700,
                              padding: '1px 6px',
                              borderRadius: '4px',
                              background: 'rgba(99, 102, 241, 0.12)',
                              color: '#6366f1'
                            }}
                          >
                            DEV
                          </span>
                        )}
                      </div>
                      <div
                        style={{
                          fontSize: '11.5px',
                          color: 'var(--webcare-text-muted, #64748b)',
                          whiteSpace: 'nowrap',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          marginTop: '2px'
                        }}
                      >
                        {item.desc}
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
                    <span
                      style={{
                        fontSize: '11px',
                        color: 'var(--webcare-text-muted, #94a3b8)',
                        background: 'var(--webcare-bg-surface, #f1f5f9)',
                        padding: '2px 8px',
                        borderRadius: '4px'
                      }}
                    >
                      {item.pillar}
                    </span>
                    <ArrowRight size={14} color={isSelected ? '#4f46e5' : 'var(--webcare-text-muted, #cbd5e1)'} />
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Footer Navigation Hints */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '10px 16px',
            borderTop: '1px solid var(--webcare-border, #e2e8f0)',
            background: 'var(--webcare-bg-surface, #f8fafc)',
            fontSize: '11px',
            color: 'var(--webcare-text-muted, #64748b)'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <span><kbd>↑</kbd> <kbd>↓</kbd> Navigate</span>
            <span><kbd>↵</kbd> Select</span>
            <span><kbd>ESC</kbd> Close</span>
          </div>
          <div>All 74 Modules &amp; Shortcuts Indexed</div>
        </div>
      </div>
    </div>
  );
};
