import React, { useRef, useState, useEffect } from 'react';
import { LucideIcon, ArrowUpRight, ChevronLeft, ChevronRight } from 'lucide-react';

export interface ContextualSubNavTab {
  id: string;
  label: string;
  icon?: LucideIcon;
  badge?: string | number;
  badgeType?: 'danger' | 'warning' | 'success' | 'info' | 'neutral';
  isActive: boolean;
  onClick: () => void;
}

export interface ContextualSubNavRelatedLink {
  id: string;
  label: string;
  icon?: LucideIcon;
  badge?: string;
  onClick: () => void;
}

export interface ContextualSubNavProps {
  sectionTitle: string;
  sectionIcon: LucideIcon;
  tabs: ContextualSubNavTab[];
  relatedLinks?: ContextualSubNavRelatedLink[];
  actions?: React.ReactNode;
  activeCountSummary?: string;
}

export const ContextualSubNav: React.FC<ContextualSubNavProps> = ({
  sectionTitle,
  sectionIcon: SectionIcon,
  tabs,
  relatedLinks,
  actions,
  activeCountSummary,
}) => {
  const scrollContainerRef = useRef<HTMLDivElement | null>(null);
  const activeTabRef = useRef<HTMLButtonElement | null>(null);
  const [canScrollLeft, setCanScrollLeft] = useState<boolean>(false);
  const [canScrollRight, setCanScrollRight] = useState<boolean>(false);

  const checkScroll = () => {
    const el = scrollContainerRef.current;
    if (!el) return;
    const { scrollLeft, scrollWidth, clientWidth } = el;
    setCanScrollLeft(scrollLeft > 6);
    setCanScrollRight(scrollLeft + clientWidth < scrollWidth - 6);
  };

  useEffect(() => {
    checkScroll();
    window.addEventListener('resize', checkScroll);
    return () => window.removeEventListener('resize', checkScroll);
  }, [tabs]);

  // Scroll active tab into view smoothly when switching
  useEffect(() => {
    if (activeTabRef.current && scrollContainerRef.current) {
      const container = scrollContainerRef.current;
      const tabEl = activeTabRef.current;
      const containerLeft = container.scrollLeft;
      const containerRight = containerLeft + container.clientWidth;
      const tabLeft = tabEl.offsetLeft;
      const tabRight = tabLeft + tabEl.clientWidth;

      if (tabLeft < containerLeft) {
        container.scrollTo({ left: Math.max(0, tabLeft - 30), behavior: 'smooth' });
      } else if (tabRight > containerRight) {
        container.scrollTo({ left: tabRight - container.clientWidth + 30, behavior: 'smooth' });
      }
    }
    checkScroll();
  }, [tabs]);

  const handleScroll = (direction: 'left' | 'right') => {
    const el = scrollContainerRef.current;
    if (!el) return;
    const scrollAmount = Math.max(160, el.clientWidth * 0.55);
    el.scrollBy({
      left: direction === 'left' ? -scrollAmount : scrollAmount,
      behavior: 'smooth',
    });
    setTimeout(checkScroll, 250);
  };

  return (
    <div className="webcare-contextual-subnav-bar">
      <div className="webcare-contextual-subnav-inner">
        {/* Left Section Label / Pillar Badge */}
        <div className="webcare-contextual-subnav-section">
          <div className="webcare-contextual-subnav-section-icon">
            <SectionIcon size={16} />
          </div>
          <div className="webcare-contextual-subnav-section-text">
            <span className="webcare-contextual-subnav-pillar">{sectionTitle}</span>
            {activeCountSummary && (
              <span className="webcare-contextual-subnav-meta">{activeCountSummary}</span>
            )}
          </div>
        </div>

        {/* Center / Primary Sub-Tabs with Scroll Controls */}
        <div className={`webcare-contextual-subnav-scroll-wrap ${canScrollLeft ? 'can-scroll-left' : ''} ${canScrollRight ? 'can-scroll-right' : ''}`}>
          {canScrollLeft && (
            <button
              type="button"
              className="webcare-subnav-scroll-arrow webcare-subnav-scroll-arrow-left"
              onClick={() => handleScroll('left')}
              title="Scroll tabs left"
              aria-label="Scroll tabs left"
            >
              <ChevronLeft size={16} />
            </button>
          )}

          <div
            className="webcare-contextual-subnav-tabs-scroll"
            ref={scrollContainerRef}
            onScroll={checkScroll}
          >
            <nav className="webcare-contextual-subnav-tabs" aria-label="Page navigation">
              {tabs.map((tab) => {
                const Icon = tab.icon;
                return (
                  <button
                    key={tab.id}
                    ref={tab.isActive ? activeTabRef : undefined}
                    type="button"
                    className={`webcare-subnav-pill-btn ${tab.isActive ? 'active' : ''}`}
                    onClick={tab.onClick}
                  >
                    {Icon && <Icon size={14} className="webcare-subnav-pill-icon" />}
                    <span className="webcare-subnav-pill-label">{tab.label}</span>
                    {tab.badge !== undefined && tab.badge !== null && tab.badge !== '' && (
                      <span className={`webcare-subnav-badge badge-${tab.badgeType || 'neutral'}`}>
                        {tab.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </nav>
          </div>

          {canScrollRight && (
            <button
              type="button"
              className="webcare-subnav-scroll-arrow webcare-subnav-scroll-arrow-right"
              onClick={() => handleScroll('right')}
              title="Scroll tabs right"
              aria-label="Scroll tabs right"
            >
              <ChevronRight size={16} />
            </button>
          )}
        </div>

        {/* Right Section: Related Companion Jumps & Context Actions */}
        <div className="webcare-contextual-subnav-right">
          {relatedLinks && relatedLinks.length > 0 && (
            <div className="webcare-contextual-subnav-related">
              <span className="webcare-related-label">Related:</span>
              {relatedLinks.map((link) => {
                const Icon = link.icon;
                return (
                  <button
                    key={link.id}
                    type="button"
                    className="webcare-subnav-related-btn"
                    onClick={link.onClick}
                    title={`Jump to ${link.label}`}
                  >
                    {Icon && <Icon size={13} />}
                    <span>{link.label}</span>
                    {link.badge && (
                      <span className="webcare-subnav-related-badge">{link.badge}</span>
                    )}
                    <ArrowUpRight size={11} className="webcare-related-arrow" />
                  </button>
                );
              })}
            </div>
          )}

          {actions && (
            <div className="webcare-contextual-subnav-actions">
              {actions}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ContextualSubNav;
