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

  const defaultTab = pillar?.default_tab || '';
  if (tabId && (tabId !== defaultTab || sectionId || Object.keys(extraArgs).length > 0)) {
    params.set('tab', tabId);
  }

  if (sectionId) {
    params.set('section', sectionId);
  }

  Object.entries(extraArgs).forEach(([k, v]) => {
    params.set(k, String(v));
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
  const page = params.get('page') || 'webcare-pro-security';
  const pillar = PILLAR_MAP[page];

  let tab = params.get('tab') || '';
  if (!tab && pillar?.default_tab) {
    tab = pillar.default_tab;
  }

  let section = params.get('section') || '';

  const activeTab = pillar?.tabs.find((t) => t.id === tab);
  if (activeTab && !section && activeTab.default_section) {
    section = activeTab.default_section;
  }

  const activeSection = activeTab?.sections?.find((s) => s.id === section);

  return {
    page,
    tab,
    section,
    pillar,
    activeTab,
    activeSection,
  };
}
