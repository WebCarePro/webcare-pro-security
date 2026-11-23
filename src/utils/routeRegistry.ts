import routesData from '../../includes/Admin/routes.json';

export interface RouteSection {
  id: string;
  label: string;
  mode: 'all' | 'developer';
}

export interface RouteTab {
  id: string;
  label: string;
  mode: 'all' | 'developer';
  group?: string;
  description?: string;
  default_section?: string;
  sections?: RouteSection[];
}

export interface RoutePillar {
  id: string;
  title: string;
  menu_title: string;
  page_title: string;
  description: string;
  bundle: string;
  icon: string;
  default_tab: string;
  mode: 'all' | 'developer';
  hidden?: boolean;
  tabs: RouteTab[];
}

export interface NavigationSchema {
  version: string;
  pillars: RoutePillar[];
}

export const navigationSchema: NavigationSchema = routesData as NavigationSchema;

export const PILLARS: RoutePillar[] = navigationSchema.pillars;

export const PILLAR_MAP: Record<string, RoutePillar> = PILLARS.reduce((acc, pillar) => {
  acc[pillar.id] = pillar;
  return acc;
}, {} as Record<string, RoutePillar>);

/**
 * Generate a canonical admin URL based on pillar, tab, section, and extra args.
 */
export function buildAdminUrl(
  pillarId: string,
  tabId: string = '',
  sectionId: string = '',
  extraArgs: Record<string, string | number> = {}
): string {
  const pillar = PILLAR_MAP[pillarId];
  const page = pillar ? pillar.id : pillarId;
  const params = new URLSearchParams();
  params.set('page', page);

  // Discard section if tabId is empty
  let effectiveTab = tabId;
  let effectiveSection = effectiveTab ? sectionId : '';

  // Validate tab and section against pillar schema if known
  if (pillar && effectiveTab) {
    const tabObj = pillar.tabs.find((t) => t.id === effectiveTab);
    if (!tabObj) {
      effectiveTab = '';
      effectiveSection = '';
    } else if (effectiveSection && tabObj.sections) {
      const secObj = tabObj.sections.find((s) => s.id === effectiveSection);
      if (!secObj) {
        effectiveSection = '';
      }
    } else if (effectiveSection && !tabObj.sections) {
      effectiveSection = '';
    }
  }

  const reservedKeys = new Set(['page', 'tab', 'section']);
  const cleanExtraArgs: Record<string, string> = {};
  Object.entries(extraArgs).forEach(([k, v]) => {
    if (!reservedKeys.has(k) && k.trim() !== '') {
      cleanExtraArgs[k] = String(v);
    }
  });

  const defaultTab = pillar?.default_tab || '';
  if (effectiveTab && (effectiveTab !== defaultTab || effectiveSection || Object.keys(cleanExtraArgs).length > 0)) {
    params.set('tab', effectiveTab);
  }

  if (effectiveSection) {
    params.set('section', effectiveSection);
  }

  Object.entries(cleanExtraArgs).forEach(([k, v]) => {
    params.set(k, v);
  });

  return `admin.php?${params.toString()}`;
}

/**
 * Navigate to a route using client-side pushState if staying on the same pillar,
 * or window.location.href if switching pillars.
 */
export function navigateToRoute(
  pillarId: string,
  tabId: string = '',
  sectionId: string = '',
  extraArgs: Record<string, string | number> = {},
  options: { replace?: boolean; onTabChange?: (tab: string, section?: string) => void } = {}
): void {
  const currentParams = new URLSearchParams(window.location.search);
  const currentPage = currentParams.get('page') || 'webcare-pro-security';

  const pillar = PILLAR_MAP[pillarId];
  const targetPage = pillar ? pillar.id : pillarId;

  const url = buildAdminUrl(targetPage, tabId, sectionId, extraArgs);

  if (currentPage === targetPage) {
    if (options.replace) {
      window.history.replaceState({ page: targetPage, tab: tabId, section: sectionId }, '', url);
    } else {
      window.history.pushState({ page: targetPage, tab: tabId, section: sectionId }, '', url);
    }
    updateDocumentTitle(targetPage, tabId, sectionId);
    try {
      window.dispatchEvent(new CustomEvent('webcare:route-change', {
        detail: { page: targetPage, tab: tabId, section: sectionId },
      }));
    } catch (_) {}
    if (options.onTabChange) {
      options.onTabChange(tabId, sectionId);
    }
  } else {
    window.location.href = url;
  }
}

/**
 * Update document title dynamically: "<Tab> — <Pillar> ‹ WebCare Pro"
 */
export function updateDocumentTitle(pillarId: string, tabId: string = '', sectionId: string = ''): void {
  const pillar = PILLAR_MAP[pillarId];
  if (!pillar) return;

  let tabLabel = '';
  if (tabId) {
    const tab = pillar.tabs.find((t) => t.id === tabId);
    if (tab) {
      tabLabel = tab.label;
      if (sectionId && tab.sections) {
        const sec = tab.sections.find((s) => s.id === sectionId);
        if (sec) {
          tabLabel = `${sec.label} · ${tab.label}`;
        }
      }
    }
  }

  if (tabLabel) {
    document.title = `${tabLabel} — ${pillar.menu_title} ‹ WebCare Pro`;
  } else {
    document.title = `${pillar.page_title} ‹ WebCare Pro`;
  }
}

/**
 * Parse current window location search parameters into a structured route.
 */
export function parseCurrentRoute(): {
  page: string;
  tab: string;
  section: string;
  pillar: RoutePillar | undefined;
  activeTab: RouteTab | undefined;
  activeSection: RouteSection | undefined;
} {
  const params = new URLSearchParams(window.location.search);
  const rawPage = params.get('page') || 'webcare-pro-security';
  const pillar = PILLAR_MAP[rawPage];
  const page = pillar ? pillar.id : rawPage;

  let rawTab = params.get('tab') || '';
  let activeTab: RouteTab | undefined = undefined;

  if (pillar) {
    if (rawTab) {
      activeTab = pillar.tabs.find((t) => t.id === rawTab);
      if (!activeTab) {
        // Invalid tab requested: normalize to default_tab
        rawTab = pillar.default_tab || '';
        activeTab = pillar.tabs.find((t) => t.id === rawTab);
      }
    } else if (pillar.default_tab) {
      rawTab = pillar.default_tab;
      activeTab = pillar.tabs.find((t) => t.id === rawTab);
    }
  }

  let rawSection = params.get('section') || '';
  let activeSection: RouteSection | undefined = undefined;

  if (activeTab) {
    if (rawSection) {
      activeSection = activeTab.sections?.find((s) => s.id === rawSection);
      if (!activeSection) {
        rawSection = activeTab.default_section || '';
        activeSection = activeTab.sections?.find((s) => s.id === rawSection);
      }
    } else if (activeTab.default_section) {
      rawSection = activeTab.default_section;
      activeSection = activeTab.sections?.find((s) => s.id === rawSection);
    }
  } else {
    rawSection = '';
  }

  // If URL had invalid tab or section, normalize URL via replaceState
  if (typeof window !== 'undefined' && window.location) {
    const currentTabParam = params.get('tab') || '';
    const currentSecParam = params.get('section') || '';
    if (currentTabParam && !activeTab) {
      params.delete('tab');
      params.delete('section');
      const newQuery = params.toString();
      const newUrl = `${window.location.pathname}${newQuery ? `?${newQuery}` : ''}`;
      window.history.replaceState({ page, tab: rawTab, section: rawSection }, '', newUrl);
    } else if (currentSecParam && !activeSection) {
      params.delete('section');
      const newQuery = params.toString();
      const newUrl = `${window.location.pathname}${newQuery ? `?${newQuery}` : ''}`;
      window.history.replaceState({ page, tab: rawTab, section: rawSection }, '', newUrl);
    }
  }

  return {
    page,
    tab: rawTab,
    section: rawSection,
    pillar,
    activeTab,
    activeSection,
  };
}
