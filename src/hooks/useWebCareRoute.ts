import { useState, useEffect, useCallback, useMemo } from '@wordpress/element';
import {
  PILLAR_MAP,
  RoutePillar,
  RouteTab,
  RouteSection,
  buildAdminUrl,
  updateDocumentTitle,
  parseCurrentRoute,
} from '../utils/routeRegistry';

export interface RouteBreadcrumb {
  label: string;
  url?: string;
  isCurrent?: boolean;
}

export interface WebCareRouteState {
  page: string;
  tab: string;
  section: string;
  pillar?: RoutePillar;
  activeTab?: RouteTab;
  activeSection?: RouteSection;
  breadcrumbs: RouteBreadcrumb[];
  isDeveloperRoute: boolean;
}

export interface NavigateOptions {
  page?: string;
  tab?: string;
  section?: string;
  extraArgs?: Record<string, string | number>;
  replace?: boolean;
}

/**
 * Single authoritative client route hook for WebCare Pro.
 * Provides unified state for page, tab, section, breadcrumbs, document title sync,
 * and seamless browser Back/Forward (popstate) handling.
 */
export function useWebCareRoute() {
  const [route, setRoute] = useState<WebCareRouteState>(() => computeRouteState());

  function computeRouteState(): WebCareRouteState {
    const parsed = parseCurrentRoute();
    const pillar = parsed.pillar;
    const activeTab = parsed.activeTab;
    const activeSection = parsed.activeSection;

    const isDeveloperRoute =
      pillar?.mode === 'developer' ||
      activeTab?.mode === 'developer' ||
      activeSection?.mode === 'developer';

    const breadcrumbs: RouteBreadcrumb[] = [
      {
        label: 'Dashboard',
        url: 'admin.php?page=webcare-pro-security',
        isCurrent: parsed.page === 'webcare-pro-security' && !parsed.tab,
      },
    ];

    if (pillar && pillar.id !== 'webcare-pro-security') {
      breadcrumbs.push({
        label: pillar.menu_title,
        url: buildAdminUrl(pillar.id),
        isCurrent: !parsed.tab,
      });
    }

    if (activeTab) {
      breadcrumbs.push({
        label: activeTab.label,
        url: buildAdminUrl(parsed.page, activeTab.id),
        isCurrent: !activeSection,
      });
    }

    if (activeSection) {
      breadcrumbs.push({
        label: activeSection.label,
        url: buildAdminUrl(parsed.page, parsed.tab, activeSection.id),
        isCurrent: true,
      });
    }

    return {
      page: parsed.page,
      tab: parsed.tab,
      section: parsed.section,
      pillar,
      activeTab,
      activeSection,
      breadcrumbs,
      isDeveloperRoute: Boolean(isDeveloperRoute),
    };
  }

  // Update on popstate (browser back/forward)
  useEffect(() => {
    const handlePopState = () => {
      const next = computeRouteState();
      setRoute(next);
      updateDocumentTitle(next.page, next.tab, next.section);
    };

    window.addEventListener('popstate', handlePopState);
    // Initial document title sync
    updateDocumentTitle(route.page, route.tab, route.section);

    return () => {
      window.removeEventListener('popstate', handlePopState);
    };
  }, []);

  const navigate = useCallback(
    ({ page, tab, section, extraArgs, replace = false }: NavigateOptions) => {
      const currentPage = route.page;
      const targetPage = page || currentPage;
      const targetTab = tab !== undefined ? tab : (targetPage === currentPage ? route.tab : '');
      const targetSection = section !== undefined ? section : '';

      const targetUrl = buildAdminUrl(targetPage, targetTab, targetSection, extraArgs);

      if (targetPage === currentPage) {
        if (replace) {
          window.history.replaceState({ page: targetPage, tab: targetTab, section: targetSection }, '', targetUrl);
        } else {
          window.history.pushState({ page: targetPage, tab: targetTab, section: targetSection }, '', targetUrl);
        }
        const next = computeRouteState();
        setRoute(next);
        updateDocumentTitle(next.page, next.tab, next.section);
      } else {
        window.location.href = targetUrl;
      }
    },
    [route.page, route.tab]
  );

  return {
    ...route,
    navigate,
    setTab: (tabId: string, sectionId: string = '') => navigate({ tab: tabId, section: sectionId }),
    setSection: (sectionId: string) => navigate({ section: sectionId }),
  };
}
