import { useState, useEffect, useCallback } from 'react';

export type WorkspaceMode = 'simple' | 'developer';

export interface UseWorkspaceModeResult {
  mode: WorkspaceMode;
  isSimpleMode: boolean;
  isDeveloperMode: boolean;
  setMode: (nextMode: WorkspaceMode) => void;
}

/**
 * Read current workspace mode from localStorage ('webcare_mode' or 'webcare_workspace_mode').
 */
const getInitialWorkspaceMode = (): WorkspaceMode => {
  try {
    const rawMode = localStorage.getItem('webcare_mode');
    if (rawMode === 'developer' || rawMode === 'simple') {
      return rawMode;
    }
    const legacyMode = localStorage.getItem('webcare_workspace_mode');
    if (legacyMode === 'advanced') {
      return 'developer';
    }
    return 'simple';
  } catch {
    return 'simple';
  }
};

/**
 * Shared hook to track and update the active workspace mode (Simple vs. Developer)
 * across all plugin views and navigation shells.
 */
export const useWorkspaceMode = (): UseWorkspaceModeResult => {
  const [mode, setModeState] = useState<WorkspaceMode>(getInitialWorkspaceMode);

  useEffect(() => {
    const handleModeChanged = (e: Event) => {
      const customEvent = e as CustomEvent<string>;
      const detail = customEvent.detail;
      if (detail === 'developer' || detail === 'simple') {
        setModeState(detail);
      } else if (detail === 'advanced') {
        setModeState('developer');
      } else if (detail === 'essential') {
        setModeState('simple');
      }
    };

    const handleStorageChanged = (e: StorageEvent) => {
      if (e.key === 'webcare_mode' && (e.newValue === 'simple' || e.newValue === 'developer')) {
        setModeState(e.newValue);
      } else if (e.key === 'webcare_workspace_mode') {
        if (e.newValue === 'advanced') setModeState('developer');
        if (e.newValue === 'essential') setModeState('simple');
      }
    };

    window.addEventListener('webcare_mode_changed', handleModeChanged);
    window.addEventListener('webcare_workspace_mode_changed', handleModeChanged);
    window.addEventListener('storage', handleStorageChanged);

    return () => {
      window.removeEventListener('webcare_mode_changed', handleModeChanged);
      window.removeEventListener('webcare_workspace_mode_changed', handleModeChanged);
      window.removeEventListener('storage', handleStorageChanged);
    };
  }, []);

  const setMode = useCallback((nextMode: WorkspaceMode) => {
    setModeState(nextMode);
    const legacyMode = nextMode === 'developer' ? 'advanced' : 'essential';
    try {
      localStorage.setItem('webcare_mode', nextMode);
      localStorage.setItem('webcare_workspace_mode', legacyMode);
      window.dispatchEvent(new CustomEvent('webcare_mode_changed', { detail: nextMode }));
      window.dispatchEvent(new CustomEvent('webcare_workspace_mode_changed', { detail: legacyMode }));
    } catch {}
  }, []);

  return {
    mode,
    isSimpleMode: mode === 'simple',
    isDeveloperMode: mode === 'developer',
    setMode,
  };
};
