import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, toFailure, type EntryMeta, type Status } from "../lib/api";
import { EntryDetail } from "./EntryDetail";
import { EntryEditor } from "./EntryEditor";
import { Generator } from "./Generator";
import { Health } from "./Health";
import { SettingsPanel } from "./SettingsPanel";
import { Button, Modal, TextInput } from "./ui";
import {
  FolderIcon,
  HeartIcon,
  LockIcon,
  PlusIcon,
  SearchIcon,
  SettingsIcon,
  ShieldIcon,
  SparklesIcon,
  StarIcon,
  TrashIcon,
} from "./Icons";
import { accentFor, formatRelative, hostOf, initials } from "../lib/format";

type View = "all" | "favorites" | "trash" | "health" | "settings";
type Sort = "recent" | "name" | "created";

export function Vault({
  status,
  onLock,
  onRefreshStatus,
  notify,
}: {
  status: Status;
  onLock: () => void;
  onRefreshStatus: () => void;
  notify: (message: string) => void;
}) {
  const [entries, setEntries] = useState<EntryMeta[]>([]);
  const [view, setView] = useState<View>("all");
  const [query, setQuery] = useState("");
  const [matches, setMatches] = useState<string[] | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [sort, setSort] = useState<Sort>("recent");
  const [editing, setEditing] = useState<EntryMeta | "new" | null>(null);
  const [showGenerator, setShowGenerator] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);

  const refresh = useCallback(async () => {
    try {
      const next = await api.listEntries();
      setEntries(next);
    } catch (failure) {
      notify(toFailure(failure).message);
    }
  }, [notify]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (query.trim().length === 0) {
      setMatches(null);
      return;
    }
    const handle = window.setTimeout(() => {
      api
        .searchEntries(query)
        .then(setMatches)
        .catch((failure) => notify(toFailure(failure).message));
    }, 140);
    return () => window.clearTimeout(handle);
  }, [query, notify]);

  const folders = useMemo(() => {
    const set = new Set<string>();
    for (const entry of entries) {
      if (entry.folder && entry.deleted_at === null) set.add(entry.folder);
    }
    return [...set].sort((a, b) => a.localeCompare(b));
  }, [entries]);

  const visible = useMemo(() => {
    const matchSet = matches === null ? null : new Set(matches);
    const list = entries.filter((entry) => {
      if (view === "trash") return entry.deleted_at !== null;
      if (entry.deleted_at !== null) return false;
      if (view === "favorites" && !entry.favorite) return false;
      if (matchSet && !matchSet.has(entry.id)) return false;
      return true;
    });
    return list.sort((a, b) => {
      if (sort === "name") return a.title.localeCompare(b.title);
      if (sort === "created") return b.created_at - a.created_at;
      return b.updated_at - a.updated_at;
    });
  }, [entries, matches, sort, view]);

  const selected = entries.find((entry) => entry.id === selectedId) ?? null;

  useEffect(() => {
    if (selectedId && !entries.some((entry) => entry.id === selectedId)) {
      setSelectedId(null);
    }
  }, [entries, selectedId]);

  useEffect(() => {
    if (visible.length > 0 && !selectedId) {
      setSelectedId(visible[0]?.id ?? null);
    }
  }, [selectedId, visible]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const ctrl = event.ctrlKey || event.metaKey;
      if (ctrl && event.key.toLowerCase() === "k") {
        event.preventDefault();
        searchRef.current?.focus();
        searchRef.current?.select();
      } else if (ctrl && event.key.toLowerCase() === "n") {
        event.preventDefault();
        setEditing("new");
      } else if (ctrl && event.key.toLowerCase() === "l") {
        event.preventDefault();
        onLock();
      } else if (ctrl && event.key.toLowerCase() === "g") {
        event.preventDefault();
        setShowGenerator(true);
      } else if (event.key === "Escape") {
        setQuery("");
      } else if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        if (editing || showGenerator) return;
        const index = visible.findIndex((entry) => entry.id === selectedId);
        if (index === -1) return;
        const next = event.key === "ArrowDown" ? index + 1 : index - 1;
        const target = visible[Math.max(0, Math.min(visible.length - 1, next))];
        if (target) {
          event.preventDefault();
          setSelectedId(target.id);
        }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [editing, onLock, selectedId, showGenerator, visible]);

  const error = useCallback((message: string) => notify(message), [notify]);

  return (
    <div className="flex h-full bg-white/60 dark:bg-zinc-950">
      <aside className="flex w-60 shrink-0 flex-col border-r border-black/5 bg-white/70 p-3 dark:border-white/10 dark:bg-zinc-900/60">
        <div className="mb-4 flex items-center gap-2 px-1">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-vault-600 text-white">
            <LockIcon className="h-4 w-4" />
          </div>
          <span className="text-sm font-semibold text-slate-900 dark:text-white">Vaultly</span>
        </div>

        <nav className="space-y-0.5" aria-label="Vault views">
          <NavItem
            active={view === "all"}
            onClick={() => setView("all")}
            icon={<ShieldIcon className="h-4 w-4" />}
            label="All items"
            count={entries.filter((entry) => entry.deleted_at === null).length}
          />
          <NavItem
            active={view === "favorites"}
            onClick={() => setView("favorites")}
            icon={<HeartIcon className="h-4 w-4" />}
            label="Favourites"
          />
          <NavItem
            active={view === "health"}
            onClick={() => setView("health")}
            icon={<SparklesIcon className="h-4 w-4" />}
            label="Password health"
          />
          <NavItem
            active={view === "trash"}
            onClick={() => setView("trash")}
            icon={<TrashIcon className="h-4 w-4" />}
            label="Trash"
            count={entries.filter((entry) => entry.deleted_at !== null).length}
          />
        </nav>

        {folders.length > 0 ? (
          <div className="mt-4 min-h-0 flex-1 overflow-y-auto">
            <p className="px-2 pb-1 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
              Folders
            </p>
            <ul className="space-y-0.5">
              {folders.map((folder) => (
                <li key={folder}>
                  <button
                    type="button"
                    onClick={() => {
                      setView("all");
                      setQuery(folder);
                    }}
                    className="flex w-full items-center gap-2 rounded-lg px-2 py-1.5 text-left text-sm text-slate-600 hover:bg-black/5 dark:text-slate-300 dark:hover:bg-white/10"
                  >
                    <FolderIcon className="h-3.5 w-3.5 shrink-0" />
                    <span className="truncate">{folder}</span>
                  </button>
                </li>
              ))}
            </ul>
          </div>
        ) : (
          <div className="flex-1" />
        )}

        <div className="space-y-0.5 border-t border-black/5 pt-2 dark:border-white/10">
          <NavItem
            active={view === "settings"}
            onClick={() => setView("settings")}
            icon={<SettingsIcon className="h-4 w-4" />}
            label="Settings"
          />
          <NavItem
            active={false}
            onClick={onLock}
            icon={<LockIcon className="h-4 w-4" />}
            label="Lock vault"
            hint="Ctrl+L"
          />
        </div>
        <button
          type="button"
          onClick={onRefreshStatus}
          className="mt-2 flex items-center gap-1.5 rounded-lg px-2 py-1 text-left text-[11px] text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
          title="Re-check protection status"
        >
          <span
            className={`h-1.5 w-1.5 rounded-full ${
              status.acl_ok ? "bg-emerald-500" : "bg-amber-500"
            }`}
          />
          Local-only · ACL {status.acl_ok ? "verified" : "warning"}
        </button>
      </aside>

      {view === "settings" ? (
        <main className="min-w-0 flex-1">
          <SettingsPanel
            status={status}
            settings={{
              auto_lock_minutes: status.auto_lock_minutes,
              capture_protection: status.capture_protection,
              clipboard_clear_seconds: status.clipboard_clear_seconds,
              theme: status.theme,
              lock_on_session_events: status.lock_on_session_events,
            }}
            onSettings={onRefreshStatus}
            onChanged={() => {
              void refresh();
              onRefreshStatus();
            }}
            onToast={notify}
            onError={error}
          />
        </main>
      ) : view === "health" ? (
        <main className="min-w-0 flex-1">
          <Health
            entries={entries}
            onSelect={(id) => {
              setView("all");
              setSelectedId(id);
            }}
            onError={error}
          />
        </main>
      ) : (
        <>
          <section className="flex w-80 shrink-0 flex-col border-r border-black/5 dark:border-white/10">
            <div className="space-y-2 p-3">
              <div className="flex items-center gap-2">
                <div className="relative flex-1">
                  <SearchIcon className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-slate-400" />
                  <TextInput
                    ref={searchRef}
                    value={query}
                    onChange={(event) => setQuery(event.target.value)}
                    placeholder="Search vault"
                    aria-label="Search vault"
                    className="pl-8"
                    spellCheck={false}
                  />
                </div>
                <Button variant="primary" onClick={() => setEditing("new")} aria-label="New entry">
                  <PlusIcon className="h-4 w-4" />
                </Button>
              </div>
              <div className="flex items-center justify-between px-1 text-xs text-slate-500 dark:text-slate-400">
                <span>
                  {view === "trash" ? "Trash" : view === "favorites" ? "Favourites" : "All items"}{" "}
                  · {visible.length}
                </span>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setShowGenerator(true)}
                    className="rounded-md px-1.5 py-0.5 hover:bg-black/5 dark:hover:bg-white/10"
                    title="Password generator (Ctrl+G)"
                  >
                    <SparklesIcon className="h-3.5 w-3.5" />
                  </button>
                  <select
                    value={sort}
                    onChange={(event) => setSort(event.target.value as Sort)}
                    aria-label="Sort entries"
                    className="bg-transparent text-xs outline-none"
                  >
                    <option value="recent">Recent</option>
                    <option value="name">Name</option>
                    <option value="created">Created</option>
                  </select>
                </div>
              </div>
            </div>

            <ul className="min-h-0 flex-1 overflow-y-auto px-2 pb-3" role="listbox" aria-label="Entries">
              {visible.length === 0 ? (
                <li className="px-2 py-8 text-center text-sm text-slate-500 dark:text-slate-400">
                  {query ? "No matches." : "No entries yet."}
                </li>
              ) : null}
              {visible.map((entry) => (
                <li key={entry.id}>
                  <button
                    type="button"
                    role="option"
                    aria-selected={entry.id === selectedId}
                    onClick={() => setSelectedId(entry.id)}
                    onDoubleClick={() => setEditing(entry)}
                    className={`mb-0.5 flex w-full items-center gap-2.5 rounded-lg px-2 py-2 text-left transition-colors ${
                      entry.id === selectedId
                        ? "bg-vault-500/12 ring-1 ring-vault-500/30 dark:bg-vault-500/20"
                        : "hover:bg-black/5 dark:hover:bg-white/5"
                    }`}
                  >
                    <span
                      className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-xs font-semibold text-white ${accentFor(entry.title)}`}
                      aria-hidden="true"
                    >
                      {initials(entry.title)}
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="flex items-center gap-1">
                        <span className="truncate text-sm font-medium text-slate-900 dark:text-slate-100">
                          {entry.title}
                        </span>
                        {entry.favorite ? (
                          <StarIcon filled className="h-3 w-3 shrink-0 text-amber-500" />
                        ) : null}
                      </span>
                      <span className="block truncate text-xs text-slate-500 dark:text-slate-400">
                        {entry.username || hostOf(entry.url) || entry.tags.join(", ") || "—"}
                      </span>
                    </span>
                    <span className="shrink-0 text-[10px] text-slate-400" aria-hidden="true">
                      {formatRelative(entry.updated_at)}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          </section>

          <main className="min-w-0 flex-1">
            {selected ? (
              <EntryDetail
                key={selected.id}
                entry={selected}
                onEdit={() => setEditing(selected)}
                onChanged={() => void refresh()}
                onCopied={notify}
                onError={error}
              />
            ) : (
              <div className="flex h-full flex-col items-center justify-center gap-3 text-center">
                <ShieldIcon className="h-10 w-10 text-slate-300 dark:text-slate-600" />
                <p className="text-sm text-slate-500 dark:text-slate-400">
                  Select an entry, or press Ctrl+N to add one.
                </p>
                <Button onClick={() => setEditing("new")}>
                  <PlusIcon className="h-4 w-4" />
                  New entry
                </Button>
              </div>
            )}
          </main>
        </>
      )}

      {editing ? (
        <EntryEditor
          {...(editing === "new" ? {} : { entry: editing })}
          onClose={() => setEditing(null)}
          onSaved={() => void refresh()}
          onCopied={notify}
        />
      ) : null}

      {showGenerator ? (
        <Modal title="Password generator" onClose={() => setShowGenerator(false)}>
          <Generator
            onCopied={(seconds) => notify(`Copied · clears in ${seconds}s`)}
            onError={(message) => {
              if (message) notify(message);
            }}
          />
        </Modal>
      ) : null}

      <datalist id="vault-folders">
        {folders.map((folder) => (
          <option key={folder} value={folder} />
        ))}
      </datalist>
    </div>
  );
}

function NavItem({
  active,
  onClick,
  icon,
  label,
  count,
  hint,
}: {
  active: boolean;
  onClick: () => void;
  icon: React.ReactNode;
  label: string;
  count?: number;
  hint?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-current={active ? "page" : undefined}
      className={`flex w-full items-center gap-2 rounded-lg px-2 py-1.5 text-sm transition-colors ${
        active
          ? "bg-vault-500/15 font-medium text-vault-800 dark:text-vault-200"
          : "text-slate-600 hover:bg-black/5 dark:text-slate-300 dark:hover:bg-white/10"
      }`}
    >
      {icon}
      <span className="flex-1 text-left">{label}</span>
      {typeof count === "number" && count > 0 ? (
        <span className="rounded-full bg-black/5 px-1.5 text-[10px] dark:bg-white/10">
          {count}
        </span>
      ) : null}
      {hint ? <span className="text-[10px] text-slate-400">{hint}</span> : null}
    </button>
  );
}
