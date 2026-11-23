import React, { createElement, useEffect, useState } from '@wordpress/element';

export type SlotComponentType = React.ComponentType<Record<string, any>>;

interface SlotEntry {
  id: string;
  priority: number;
  component: SlotComponentType;
}

class WebCareModuleSlotRegistry {
  private slots: Record<string, SlotEntry[]> = {};
  private listeners: Set<() => void> = new Set();

  public registerSlot(slotName: string, id: string, component: SlotComponentType, priority = 10): void {
    if (!slotName || !component) return;
    if (!this.slots[slotName]) {
      this.slots[slotName] = [];
    }
    const existingIdx = this.slots[slotName].findIndex((s) => s.id === id);
    const entry: SlotEntry = { id, priority, component };
    if (existingIdx >= 0) {
      this.slots[slotName][existingIdx] = entry;
    } else {
      this.slots[slotName].push(entry);
    }
    this.slots[slotName].sort((a, b) => a.priority - b.priority);
    this.listeners.forEach((fn) => fn());
  }

  public getSlotComponents(slotName: string): SlotEntry[] {
    return this.slots[slotName] || [];
  }

  public subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }
}

const globalAny = window as unknown as {
  webCareModuleRegistry?: WebCareModuleSlotRegistry;
};

if (!globalAny.webCareModuleRegistry) {
  globalAny.webCareModuleRegistry = new WebCareModuleSlotRegistry();
}

export const webCareModuleRegistry = globalAny.webCareModuleRegistry;

export const WebCareSlot: React.FC<{ name: string; context?: Record<string, any> }> = ({ name, context = {} }) => {
  const [, setTick] = useState(0);

  useEffect(() => {
    return webCareModuleRegistry.subscribe(() => setTick((t) => t + 1));
  }, []);

  const entries = webCareModuleRegistry.getSlotComponents(name);
  if (!entries.length) {
    return null;
  }

  return createElement(
    'div',
    { style: { display: 'flex', flexDirection: 'column', gap: '12px' } },
    entries.map((entry) => createElement(entry.component, { key: entry.id, ...context }))
  );
};
