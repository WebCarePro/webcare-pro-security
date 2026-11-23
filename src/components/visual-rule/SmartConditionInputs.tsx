import React, { useState, useRef, useEffect, useMemo } from '@wordpress/element';
import { ChevronDown, Globe, Package, Palette, X, Plus, LocateFixed } from 'lucide-react';
import { COUNTRY_CATALOG, COUNTRY_BY_CODE, formatCountryBadgeLabel } from '../../utils/countryCatalog';

export interface InstalledComponentOption {
  slug: string;
  name: string;
  version?: string;
  type: 'plugin' | 'theme' | 'mu-plugin';
  status: 'active' | 'inactive' | 'must-use';
  url_path: string;
}

export interface WpRoleOption {
  slug: string;
  label: string;
}

interface SmartConditionInputProps {
  field: string;
  op: string;
  value: string;
  onChangeValue: (val: string) => void;
  onSuggestOp?: (nextOp: string) => void;
  installedComponents: InstalledComponentOption[];
  roles: WpRoleOption[];
  currentIp?: string;
  discoveredEndpoints?: { ajax_actions: string[]; rest_routes: string[] };
}

function splitListTokens(raw: string): string[] {
  return (raw || '')
    .split(/[\s,]+/)
    .map((t) => t.trim())
    .filter(Boolean);
}

/**
 * Searchable Country Selector supporting typing by country name OR ISO-2 code,
 * single-select or multi-select tag chips, and manual ISO-2 entry.
 */
const CountrySelector: React.FC<{
  op: string;
  value: string;
  onChangeValue: (val: string) => void;
}> = ({ op, value, onChangeValue }) => {
  const isMulti = op === 'in' || op === 'not_in';
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');
  const [highlightIdx, setHighlightIdx] = useState(0);
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const inputFocusedRef = useRef(false);

  const selectedCodes = useMemo(() => {
    if (!isMulti) return value.trim() ? [value.trim().toUpperCase()] : [];
    return Array.from(new Set(splitListTokens(value).map((c) => c.toUpperCase())));
  }, [value, isMulti]);

  useEffect(() => {
    // Only hydrate formatted display label when user is not actively typing in the box
    if (!isMulti && !inputFocusedRef.current) {
      const clean = value.trim().toUpperCase();
      setSearch(clean ? formatCountryBadgeLabel(clean) : '');
    }
  }, [value, isMulti]);

  useEffect(() => {
    const onDocClick = (e: MouseEvent) => {
      if (wrapRef.current && e.target instanceof Node && !wrapRef.current.contains(e.target)) {
        setOpen(false);
        inputFocusedRef.current = false;
      }
    };
    document.addEventListener('mousedown', onDocClick);
    return () => document.removeEventListener('mousedown', onDocClick);
  }, []);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    const selectedLabel = !isMulti && value.trim() ? formatCountryBadgeLabel(value.trim()).toLowerCase() : '';
    const effectiveQ = !isMulti && q === selectedLabel ? '' : q;
    if (!effectiveQ) {
      return COUNTRY_CATALOG.slice(0, 60);
    }

    const scored: Array<{ rank: number; item: (typeof COUNTRY_CATALOG)[number] }> = [];
    for (const c of COUNTRY_CATALOG) {
      const nameL = c.name.toLowerCase();
      const codeL = c.code.toLowerCase();
      const aliasL = (c.aliases || '').toLowerCase();
      if (codeL === effectiveQ) {
        scored.push({ rank: 0, item: c });
      } else if (nameL.startsWith(effectiveQ)) {
        scored.push({ rank: 1, item: c });
      } else if (aliasL && aliasL.split(/\s+/).some((w) => w.startsWith(effectiveQ))) {
        scored.push({ rank: 2, item: c });
      } else if (nameL.includes(effectiveQ) || aliasL.includes(effectiveQ)) {
        scored.push({ rank: 3, item: c });
      }
    }
    scored.sort((a, b) => a.rank - b.rank || a.item.name.localeCompare(b.item.name));
    return scored.slice(0, 60).map((s) => s.item);
  }, [search, value, isMulti]);

  const pickCountry = (code: string) => {
    const upper = code.trim().toUpperCase();
    if (!upper) return;
    if (isMulti) {
      const next = Array.from(new Set([...selectedCodes, upper]));
      onChangeValue(next.join(', '));
      setSearch('');
      setHighlightIdx(0);
    } else {
      inputFocusedRef.current = false;
      onChangeValue(upper);
      setSearch(formatCountryBadgeLabel(upper));
      setOpen(false);
    }
  };

  const commitTypedCountryOnBlur = () => {
    inputFocusedRef.current = false;
    if (isMulti) return;
    const trimmed = search.trim();
    if (!trimmed) {
      onChangeValue('');
      return;
    }
    const formatted = formatCountryBadgeLabel(value.trim().toUpperCase());
    if (value.trim() && trimmed === formatted) {
      return;
    }
    const exactName = COUNTRY_CATALOG.find((c) => c.name.toLowerCase() === trimmed.toLowerCase());
    if (exactName) {
      onChangeValue(exactName.code);
      setSearch(formatCountryBadgeLabel(exactName.code));
      return;
    }
    if (/^[A-Za-z0-9]{2}$/.test(trimmed)) {
      const upper = trimmed.toUpperCase();
      onChangeValue(upper);
      setSearch(formatCountryBadgeLabel(upper));
    }
  };

  const removeChip = (code: string) => {
    const next = selectedCodes.filter((c) => c !== code);
    onChangeValue(next.join(', '));
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setOpen(true);
      setHighlightIdx((i) => Math.min(filtered.length - 1, i + 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setHighlightIdx((i) => Math.max(0, i - 1));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const clean = search.trim();
      if (/^[A-Za-z0-9]{2}$/.test(clean) && !filtered[highlightIdx]?.name.toLowerCase().startsWith(clean.toLowerCase())) {
        pickCountry(clean.toUpperCase());
      } else if (open && filtered[highlightIdx]) {
        pickCountry(filtered[highlightIdx].code);
      } else if (/^[A-Za-z0-9]{2}$/.test(clean)) {
        pickCountry(clean.toUpperCase());
      }
    } else if (e.key === 'Backspace' && isMulti && search === '' && selectedCodes.length > 0) {
      removeChip(selectedCodes[selectedCodes.length - 1]);
    } else if (e.key === 'Escape') {
      setOpen(false);
    }
  };

  return (
    <div ref={wrapRef} className="webcare-smart-combobox">
      <div
        className="webcare-smart-input-shell"
        onClick={() => setOpen(true)}
      >
        <Globe size={14} className="webcare-smart-input-icon" />
        {isMulti && selectedCodes.length > 0 && (
          <div className="webcare-smart-chips">
            {selectedCodes.map((code) => (
              <span key={code} className="webcare-smart-chip">
                <span>{COUNTRY_BY_CODE[code] ? `${COUNTRY_BY_CODE[code].name} (${code})` : code}</span>
                <button
                  type="button"
                  onClick={(ev) => {
                    ev.stopPropagation();
                    removeChip(code);
                  }}
                  aria-label={`Remove ${code}`}
                >
                  <X size={11} />
                </button>
              </span>
            ))}
          </div>
        )}
        <input
          type="text"
          className="webcare-smart-bare-input"
          placeholder="Select or type country..."
          value={search}
          onFocus={() => {
            inputFocusedRef.current = true;
            setOpen(true);
            if (!isMulti && value.trim() && search === formatCountryBadgeLabel(value.trim().toUpperCase())) {
              // Allow typing seamlessly without accidentally appending to "(US)"
              setSearch('');
            }
          }}
          onBlur={() => {
            // Delay slightly so option click triggers before blur commit
            setTimeout(() => commitTypedCountryOnBlur(), 150);
          }}
          onChange={(e) => {
            const nextVal = e.target.value;
            inputFocusedRef.current = true;
            setSearch(nextVal);
            setOpen(true);
            setHighlightIdx(0);
            if (!isMulti) {
              const trimmed = nextVal.trim();
              if (trimmed === '') {
                onChangeValue('');
              } else {
                const exactName = COUNTRY_CATALOG.find((c) => c.name.toLowerCase() === trimmed.toLowerCase());
                if (exactName) {
                  onChangeValue(exactName.code);
                }
              }
            }
          }}
          onKeyDown={handleKeyDown}
        />
        <button
          type="button"
          className="webcare-smart-chevron-btn"
          onClick={(ev) => {
            ev.stopPropagation();
            setOpen((o) => !o);
          }}
          aria-label="Toggle country list"
        >
          <ChevronDown size={14} />
        </button>
      </div>

      {open && (
        <div className="webcare-smart-dropdown" role="listbox">
          {filtered.length === 0 ? (
            <div className="webcare-smart-empty">
              {/^[A-Za-z0-9]{2}$/.test(search.trim()) ? (
                <button
                  type="button"
                  className="webcare-smart-option is-highlighted"
                  onClick={() => pickCountry(search.trim().toUpperCase())}
                >
                  Use manual ISO-2 code &ldquo;{search.trim().toUpperCase()}&rdquo;
                </button>
              ) : (
                <span>No matching country. Type a country name or 2-letter code (e.g. US, BD).</span>
              )}
            </div>
          ) : (
            filtered.map((c, idx) => {
              const isSelected = selectedCodes.includes(c.code);
              return (
                <button
                  key={c.code}
                  type="button"
                  role="option"
                  aria-selected={isSelected}
                  className={`webcare-smart-option ${idx === highlightIdx ? 'is-highlighted' : ''} ${isSelected ? 'is-selected' : ''}`}
                  onMouseEnter={() => setHighlightIdx(idx)}
                  onClick={() => pickCountry(c.code)}
                >
                  <span className="webcare-smart-option-main">{c.name}</span>
                  <span className="webcare-smart-option-code">{c.code}</span>
                </button>
              );
            })
          )}
        </div>
      )}
    </div>
  );
};

/**
 * Combobox for Installed Plugins/Themes: works both for `wp.plugin.target_slug` (slug picker + manual slug)
 * AND for `http.request.uri.path` (manual URL path + 1-click installed plugin/theme path helper).
 */
const PluginThemePicker: React.FC<{
  mode: 'slug' | 'uri';
  op: string;
  value: string;
  onChangeValue: (val: string) => void;
  onSuggestOp?: (nextOp: string) => void;
  installedComponents: InstalledComponentOption[];
}> = ({ mode, op, value, onChangeValue, onSuggestOp, installedComponents }) => {
  const isMultiSlug = mode === 'slug' && (op === 'in' || op === 'not_in');
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const wrapRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const onDocClick = (e: MouseEvent) => {
      if (wrapRef.current && e.target instanceof Node && !wrapRef.current.contains(e.target)) {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', onDocClick);
    return () => document.removeEventListener('mousedown', onDocClick);
  }, []);

  const selectedSlugs = useMemo(
    () => (isMultiSlug ? Array.from(new Set(splitListTokens(value).map((s) => s.toLowerCase()))) : []),
    [value, isMultiSlug]
  );

  const filteredComponents = useMemo(() => {
    const q = (mode === 'slug' && !isMultiSlug ? value : query).trim().toLowerCase();
    if (!q) return installedComponents;
    return installedComponents.filter(
      (c) =>
        c.name.toLowerCase().includes(q) ||
        c.slug.toLowerCase().includes(q) ||
        c.url_path.toLowerCase().includes(q)
    );
  }, [installedComponents, mode, isMultiSlug, value, query]);

  const handleSelectComponent = (comp: InstalledComponentOption) => {
    if (mode === 'uri') {
      onChangeValue(comp.url_path);
      if (op === 'eq' && onSuggestOp) {
        onSuggestOp('starts_with');
      }
      setOpen(false);
      setQuery('');
      return;
    }

    if (isMultiSlug) {
      const next = Array.from(new Set([...selectedSlugs, comp.slug.toLowerCase()]));
      onChangeValue(next.join(', '));
      setQuery('');
    } else {
      onChangeValue(comp.slug);
      setOpen(false);
    }
  };

  const plugins = filteredComponents.filter((c) => c.type !== 'theme');
  const themes = filteredComponents.filter((c) => c.type === 'theme');

  const renderComponentOption = (c: InstalledComponentOption, keyPrefix: string) => {
    const isActive = c.status === 'active' || c.status === 'must-use';
    const Icon = c.type === 'theme' ? Palette : Package;
    return (
      <button
        key={`${keyPrefix}:${c.slug}`}
        type="button"
        className="webcare-smart-option webcare-smart-option-stacked"
        onClick={() => handleSelectComponent(c)}
      >
        <span className="webcare-smart-comp-top">
          <span className="webcare-smart-comp-left">
            <Icon size={14} className="webcare-smart-comp-icon" />
            <strong className="webcare-smart-comp-name">{c.name}</strong>
          </span>
          <span className="webcare-smart-comp-meta">
            {c.version ? <span className="webcare-smart-version">v{c.version}</span> : null}
            <span className={`webcare-smart-status ${isActive ? 'is-active' : 'is-inactive'}`}>
              {c.status}
            </span>
          </span>
        </span>
        <span className="webcare-smart-comp-path">
          {mode === 'uri' ? c.url_path : `${c.slug} · ${c.url_path}`}
        </span>
      </button>
    );
  };

  if (mode === 'uri') {
    return (
      <div ref={wrapRef} className="webcare-smart-combobox webcare-smart-uri-combo">
        <div className="webcare-smart-uri-row">
          <input
            type="text"
            className="webcare-input webcare-smart-uri-input"
            placeholder=""
            value={value}
            onChange={(e) => onChangeValue(e.target.value)}
          />
          <button
            type="button"
            className="webcare-btn-micro webcare-smart-picker-trigger"
            onClick={() => setOpen((o) => !o)}
            title="Pick installed Plugin or Theme URL"
          >
            <Package size={13} />
            <span>Plugins / Themes</span>
            <ChevronDown size={12} />
          </button>
        </div>

        {open && (
          <div className="webcare-smart-dropdown webcare-smart-dropdown-wide">
            <div className="webcare-smart-dropdown-search">
              <input
                type="text"
                className="webcare-input webcare-smart-search-input"
                placeholder="Search installed plugins or themes..."
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                autoFocus
              />
            </div>
            <div className="webcare-smart-dropdown-scroll">
              {filteredComponents.length === 0 ? (
                <div className="webcare-smart-empty">No matching installed plugin/theme. Type any path manually in the box.</div>
              ) : (
                <>
                  {plugins.length > 0 && (
                    <div className="webcare-smart-group-label">Installed Plugins ({plugins.length})</div>
                  )}
                  {plugins.map((c) => renderComponentOption(c, 'p'))}
                  {themes.length > 0 && (
                    <div className="webcare-smart-group-label">Installed Themes ({themes.length})</div>
                  )}
                  {themes.map((c) => renderComponentOption(c, 't'))}
                </>
              )}
            </div>
          </div>
        )}
      </div>
    );
  }

  return (
    <div ref={wrapRef} className="webcare-smart-combobox">
      <div className="webcare-smart-input-shell" onClick={() => setOpen(true)}>
        <Package size={14} className="webcare-smart-input-icon" />
        {isMultiSlug && selectedSlugs.length > 0 && (
          <div className="webcare-smart-chips">
            {selectedSlugs.map((slug) => (
              <span key={slug} className="webcare-smart-chip">
                <span>{slug}</span>
                <button
                  type="button"
                  onClick={(ev) => {
                    ev.stopPropagation();
                    onChangeValue(selectedSlugs.filter((s) => s !== slug).join(', '));
                  }}
                >
                  <X size={11} />
                </button>
              </span>
            ))}
          </div>
        )}
        <input
          type="text"
          className="webcare-smart-bare-input"
          placeholder={isMultiSlug ? 'Select or type slug...' : 'Select or type slug...'}
          value={isMultiSlug ? query : value}
          onFocus={() => setOpen(true)}
          onChange={(e) => {
            if (isMultiSlug) {
              setQuery(e.target.value);
            } else {
              onChangeValue(e.target.value);
            }
            setOpen(true);
          }}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && isMultiSlug && query.trim()) {
              e.preventDefault();
              const next = Array.from(new Set([...selectedSlugs, query.trim().toLowerCase()]));
              onChangeValue(next.join(', '));
              setQuery('');
            } else if (e.key === 'Escape') {
              setOpen(false);
            }
          }}
        />
        <button
          type="button"
          className="webcare-smart-chevron-btn"
          onClick={(ev) => {
            ev.stopPropagation();
            setOpen((o) => !o);
          }}
          aria-label="Toggle installed plugins and themes"
        >
          <ChevronDown size={14} />
        </button>
      </div>

      {open && (
        <div className="webcare-smart-dropdown webcare-smart-dropdown-wide">
          <div className="webcare-smart-dropdown-scroll">
            {plugins.length > 0 && <div className="webcare-smart-group-label">Installed Plugins ({plugins.length})</div>}
            {plugins.map((c) => renderComponentOption(c, 'ps'))}

            {themes.length > 0 && <div className="webcare-smart-group-label">Installed Themes ({themes.length})</div>}
            {themes.map((c) => renderComponentOption(c, 'ts'))}

            {(isMultiSlug ? query : value).trim() !== '' && (
              <button
                type="button"
                className="webcare-smart-option is-highlighted"
                onClick={() => {
                  const rawSlug = (isMultiSlug ? query : value).trim();
                  if (isMultiSlug) {
                    const next = Array.from(new Set([...selectedSlugs, rawSlug.toLowerCase()]));
                    onChangeValue(next.join(', '));
                    setQuery('');
                  } else {
                    onChangeValue(rawSlug);
                    setOpen(false);
                  }
                }}
              >
                <span className="webcare-smart-option-title">
                  <Plus size={13} /> Use manual slug: <code>{(isMultiSlug ? query : value).trim()}</code>
                </span>
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

const HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];
const COMMON_UPLOAD_EXTS = ['php', 'phtml', 'phar', 'php5', 'svg', 'js', 'exe', 'sh'];

export const SmartConditionValueInput: React.FC<SmartConditionInputProps> = ({
  field,
  op,
  value,
  onChangeValue,
  onSuggestOp,
  installedComponents,
  roles,
  currentIp,
  discoveredEndpoints,
}) => {
  if (field === 'ip.geoip.country') {
    return <CountrySelector op={op} value={value} onChangeValue={onChangeValue} />;
  }

  if (field === 'wp.plugin.target_slug') {
    return (
      <PluginThemePicker
        mode="slug"
        op={op}
        value={value}
        onChangeValue={onChangeValue}
        installedComponents={installedComponents}
      />
    );
  }

  if (field === 'http.request.uri.path') {
    return (
      <PluginThemePicker
        mode="uri"
        op={op}
        value={value}
        onChangeValue={onChangeValue}
        onSuggestOp={onSuggestOp}
        installedComponents={installedComponents}
      />
    );
  }

  if (field === 'http.request.method') {
    if (op === 'eq' || op === 'ne') {
      return (
        <select
          className="webcare-input"
          value={HTTP_METHODS.includes(value.toUpperCase()) ? value.toUpperCase() : value}
          onChange={(e) => onChangeValue(e.target.value)}
        >
          <option value="">Select HTTP Method...</option>
          {HTTP_METHODS.map((m) => (
            <option key={m} value={m}>{m}</option>
          ))}
        </select>
      );
    }
    const chosen = new Set(splitListTokens(value).map((m) => m.toUpperCase()));
    return (
      <div className="webcare-smart-pill-group">
        {HTTP_METHODS.map((m) => {
          const active = chosen.has(m);
          return (
            <button
              key={m}
              type="button"
              className={`webcare-smart-toggle-chip ${active ? 'is-active' : ''}`}
              onClick={() => {
                const next = new Set(chosen);
                if (active) next.delete(m);
                else next.add(m);
                onChangeValue(Array.from(next).join(', '));
              }}
            >
              {m}
            </button>
          );
        })}
      </div>
    );
  }

  if (field === 'wp.user.role') {
    const roleList = roles.length > 0
      ? roles
      : [
          { slug: 'administrator', label: 'Administrator' },
          { slug: 'editor', label: 'Editor' },
          { slug: 'author', label: 'Author' },
          { slug: 'subscriber', label: 'Subscriber' },
          { slug: 'customer', label: 'Customer' },
        ];
    const chosen = new Set(splitListTokens(value).map((r) => r.toLowerCase()));
    return (
      <div className="webcare-smart-stack">
        <div className="webcare-smart-pill-group">
          {roleList.map((r) => {
            const active = chosen.has(r.slug);
            return (
              <button
                key={r.slug}
                type="button"
                className={`webcare-smart-toggle-chip ${active ? 'is-active' : ''}`}
                onClick={() => {
                  const next = new Set(chosen);
                  if (active) next.delete(r.slug);
                  else next.add(r.slug);
                  onChangeValue(Array.from(next).join(', '));
                }}
              >
                {r.label}
              </button>
            );
          })}
        </div>
        <input
          type="text"
          className="webcare-input"
          placeholder="Or type role slugs (comma separated)..."
          value={value}
          onChange={(e) => onChangeValue(e.target.value)}
        />
      </div>
    );
  }

  if (field === 'http.upload.extension') {
    const chosen = new Set(splitListTokens(value).map((x) => x.toLowerCase().replace(/^\./, '')));
    return (
      <div className="webcare-smart-stack">
        <input
          type="text"
          className="webcare-input"
          placeholder=""
          value={value}
          onChange={(e) => onChangeValue(e.target.value)}
        />
        {op !== 'matches_regex' && (
          <div className="webcare-smart-pill-group">
            {COMMON_UPLOAD_EXTS.map((ext) => {
              const active = chosen.has(ext);
              return (
                <button
                  key={ext}
                  type="button"
                  className={`webcare-smart-toggle-chip ${active ? 'is-active' : ''}`}
                  onClick={() => {
                    if (op === 'eq') {
                      onChangeValue(ext);
                    } else {
                      const next = new Set(chosen);
                      if (active) next.delete(ext);
                      else next.add(ext);
                      onChangeValue(Array.from(next).join(', '));
                    }
                  }}
                >
                  .{ext}
                </button>
              );
            })}
          </div>
        )}
      </div>
    );
  }

  if (field === 'ip.src') {
    const isCidr = op === 'in_cidr' || op === 'not_in_cidr';
    return (
      <div className="webcare-smart-uri-row">
        <input
          type="text"
          className="webcare-input webcare-smart-uri-input"
          placeholder=""
          value={value}
          onChange={(e) => onChangeValue(e.target.value)}
        />
        {currentIp && (
          <button
            type="button"
            className="webcare-btn-micro webcare-smart-picker-trigger"
            onClick={() => {
              if (isCidr && value.trim()) {
                const items = Array.from(new Set([...splitListTokens(value), currentIp]));
                onChangeValue(items.join(', '));
              } else {
                onChangeValue(currentIp);
              }
            }}
            title={`Fill your current IP (${currentIp})`}
          >
            <LocateFixed size={13} />
            <span>My IP ({currentIp})</span>
          </button>
        )}
      </div>
    );
  }

  if (field === 'wp.ajax.action' || field === 'wp.rest.route') {
    const listId = `webcare-ep-${field.replace(/\./g, '-')}`;
    const opts = field === 'wp.ajax.action'
      ? (discoveredEndpoints?.ajax_actions || [])
      : (discoveredEndpoints?.rest_routes || []);
    return (
      <div className="webcare-smart-uri-row">
        <input
          type="text"
          list={opts.length > 0 ? listId : undefined}
          className="webcare-input webcare-smart-uri-input"
          placeholder=""
          value={value}
          onChange={(e) => onChangeValue(e.target.value)}
        />
        {opts.length > 0 && (
          <datalist id={listId}>
            {opts.map((ep) => (
              <option key={ep} value={ep} />
            ))}
          </datalist>
        )}
      </div>
    );
  }

  return (
    <input
      type="text"
      className="webcare-input"
      placeholder=""
      value={value}
      onChange={(e) => onChangeValue(e.target.value)}
    />
  );
};
