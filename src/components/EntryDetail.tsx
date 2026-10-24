import { useEffect, useState } from "react";
import {
  api,
  toFailure,
  type EntryMeta,
  type SecretField,
  type TotpCode,
} from "../lib/api";
import { Button, Modal } from "./ui";
import {
  ClockIcon,
  CopyIcon,
  EyeIcon,
  EyeOffIcon,
  FolderIcon,
  StarIcon,
  TrashIcon,
} from "./Icons";
import { accentFor, formatRelative, hostOf, initials, kindLabel } from "../lib/format";

const REVEAL_MS = 20_000;

function SecretRow({
  label,
  value,
  masked = true,
  onCopied,
  onError,
}: {
  label: string;
  value: string;
  masked?: boolean;
  onCopied: (message: string) => void;
  onError: (message: string) => void;
}) {
  const [revealed, setRevealed] = useState(!masked);

  useEffect(() => {
    if (!revealed || !masked) return;
    const timer = window.setTimeout(() => setRevealed(false), REVEAL_MS);
    return () => window.clearTimeout(timer);
  }, [revealed, masked]);

  if (!value) return null;

  return (
    <div className="group flex items-center gap-2 rounded-lg px-2 py-1.5 hover:bg-black/5 dark:hover:bg-white/5">
      <span className="w-28 shrink-0 text-xs font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400">
        {label}
      </span>
      <span className="min-w-0 flex-1 truncate font-mono text-sm text-slate-800 dark:text-slate-100">
        {masked && !revealed ? "•".repeat(Math.min(value.length, 18)) : value}
      </span>
      <div className="flex shrink-0 items-center gap-0.5 opacity-70 transition-opacity group-hover:opacity-100">
        {masked ? (
          <Button
            variant="ghost"
            aria-label={revealed ? `Hide ${label}` : `Reveal ${label}`}
            className="px-2 py-1"
            onClick={() => setRevealed((current) => !current)}
          >
            {revealed ? (
              <EyeOffIcon className="h-4 w-4" />
            ) : (
              <EyeIcon className="h-4 w-4" />
            )}
          </Button>
        ) : null}
        <Button
          variant="ghost"
          aria-label={`Copy ${label}`}
          className="px-2 py-1"
          onClick={async () => {
            try {
              const result = await api.copyText(value);
              onCopied(`${label} copied · clears in ${result.seconds}s`);
            } catch (failure) {
              onError(toFailure(failure).message);
            }
          }}
        >
          <CopyIcon className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}

function TotpDisplay({
  id,
  onCopied,
  onError,
}: {
  id: string;
  onCopied: (message: string) => void;
  onError: (message: string) => void;
}) {
  const [code, setCode] = useState<TotpCode | null>(null);
  const [seconds, setSeconds] = useState(30);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let alive = true;
    let timer: number | undefined;
    const load = async () => {
      try {
        const next = await api.totpCode(id);
        if (!alive) return;
        setCode(next);
        setSeconds(next.seconds_remaining);
        timer = window.setTimeout(load, next.seconds_remaining * 1000 + 50);
      } catch (failure) {
        if (!alive) return;
        setFailed(true);
        onError(toFailure(failure).message);
      }
    };
    void load();
    const tick = window.setInterval(() => setSeconds((value) => Math.max(0, value - 1)), 1000);
    return () => {
      alive = false;
      if (timer) window.clearTimeout(timer);
      window.clearInterval(tick);
    };
  }, [id, onError]);

  if (failed) return null;

  return (
    <div className="flex items-center gap-3 rounded-xl border border-vault-500/30 bg-vault-50 px-3 py-2 dark:border-vault-500/40 dark:bg-vault-950/40">
      <span className="text-xs font-semibold uppercase tracking-wide text-vault-700 dark:text-vault-300">
        One-time code
      </span>
      <span className="font-mono text-lg tracking-[0.2em] text-slate-900 dark:text-white">
        {code ? code.code.replace(/(\d{3})(\d{3})/, "$1 $2") : "……"}
      </span>
      <span className="text-xs text-slate-500 dark:text-slate-400">{seconds}s</span>
      <Button
        variant="ghost"
        className="ml-auto px-2 py-1"
        aria-label="Copy one-time code"
        disabled={!code}
        onClick={async () => {
          if (!code) return;
          try {
            const result = await api.copyText(code.code);
            onCopied(`One-time code copied · clears in ${result.seconds}s`);
          } catch (failure) {
            onError(toFailure(failure).message);
          }
        }}
      >
        <CopyIcon className="h-4 w-4" />
      </Button>
    </div>
  );
}

export function EntryDetail({
  entry,
  onEdit,
  onChanged,
  onCopied,
  onError,
}: {
  entry: EntryMeta;
  onEdit: () => void;
  onChanged: () => void;
  onCopied: (message: string) => void;
  onError: (message: string) => void;
}) {
  const [history, setHistory] = useState<number[] | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [custom, setCustom] = useState<{ label: string; value: string }[] | null>(null);

  useEffect(() => {
    setHistory(null);
    setCustom(null);
  }, [entry.id]);

  const deleted = entry.deleted_at !== null;

  const copy = async (field: SecretField) => {
    try {
      const result = await api.copyField(entry.id, field);
      onCopied(`Copied · clipboard clears in ${result.seconds}s`);
    } catch (failure) {
      onError(toFailure(failure).message);
    }
  };

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-start gap-4 border-b border-black/5 p-6 dark:border-white/10">
        <div
          className={`flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl text-lg font-semibold text-white ${accentFor(entry.title)}`}
          aria-hidden="true"
        >
          {initials(entry.title)}
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <h2 className="truncate text-xl font-semibold text-slate-900 dark:text-white">
              {entry.title}
            </h2>
            {entry.favorite ? (
              <StarIcon filled className="h-4 w-4 text-amber-500" aria-label="Favourite" />
            ) : null}
          </div>
          <p className="mt-0.5 truncate text-sm text-slate-500 dark:text-slate-400">
            {kindLabel(entry.kind)}
            {entry.username ? ` · ${entry.username}` : ""}
            {entry.url ? ` · ${hostOf(entry.url)}` : ""}
          </p>
          <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
            <span>Updated {formatRelative(entry.updated_at)}</span>
            {entry.folder ? (
              <span className="inline-flex items-center gap-1 rounded-full bg-black/5 px-2 py-0.5 dark:bg-white/10">
                <FolderIcon className="h-3 w-3" />
                {entry.folder}
              </span>
            ) : null}
            {entry.tags.map((tag) => (
              <span
                key={tag}
                className="rounded-full bg-vault-500/10 px-2 py-0.5 text-vault-700 dark:text-vault-300"
              >
                {tag}
              </span>
            ))}
          </div>
        </div>
        <div className="flex shrink-0 gap-2">
          {deleted ? (
            <Button
              onClick={async () => {
                try {
                  await api.restoreEntry(entry.id);
                  onChanged();
                  onCopied("Entry restored");
                } catch (failure) {
                  onError(toFailure(failure).message);
                }
              }}
            >
              Restore
            </Button>
          ) : (
            <>
              <Button onClick={onEdit}>Edit</Button>
              <Button
                variant="ghost"
                aria-label="Move to trash"
                onClick={() => setConfirmDelete(true)}
              >
                <TrashIcon className="h-4 w-4" />
              </Button>
            </>
          )}
        </div>
      </header>

      <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-6">
        {deleted ? (
          <p className="rounded-xl border border-rose-500/30 bg-rose-50 p-3 text-sm text-rose-700 dark:bg-rose-950/30 dark:text-rose-300">
            This entry is in the trash
            {entry.deleted_at
              ? ` and will be permanently deleted in ${30 - Math.min(29, Math.floor((Date.now() - entry.deleted_at) / 86_400_000))} days`
              : ""}
            .
          </p>
        ) : null}

        {entry.username ? (
          <SecretRow
            label="Username"
            value={entry.username}
            masked={false}
            onCopied={onCopied}
            onError={onError}
          />
        ) : null}

        {entry.url ? (
          <SecretRow
            label="Website"
            value={entry.url}
            masked={false}
            onCopied={onCopied}
            onError={onError}
          />
        ) : null}

        {entry.kind === "login" ? (
          <div className="flex items-center gap-2">
            <Button variant="primary" onClick={() => void copy("password")}>
              <CopyIcon className="h-4 w-4" />
              Copy password
            </Button>
            {entry.has_totp ? (
              <Button onClick={() => void copy("totp_secret")}>Copy TOTP secret</Button>
            ) : null}
          </div>
        ) : null}

        {entry.has_totp ? (
          <TotpDisplay id={entry.id} onCopied={onCopied} onError={onError} />
        ) : null}

        {entry.kind === "card" ? (
          <div className="flex flex-wrap gap-2">
            <Button variant="primary" onClick={() => void copy("card_number")}>
              <CopyIcon className="h-4 w-4" />
              Copy card number
            </Button>
            <Button onClick={() => void copy("card_expiry")}>Copy expiry</Button>
            <Button onClick={() => void copy("card_cvv")}>Copy CVV</Button>
            <Button onClick={() => void copy("card_pin")}>Copy PIN</Button>
          </div>
        ) : null}

        {entry.kind === "identity" ? (
          <div className="flex flex-wrap gap-2">
            <Button variant="primary" onClick={() => void copy("identity_full_name")}>
              Copy name
            </Button>
            <Button onClick={() => void copy("identity_email")}>Copy e-mail</Button>
            <Button onClick={() => void copy("identity_phone")}>Copy phone</Button>
          </div>
        ) : null}

        {entry.has_notes ? (
          <div className="space-y-1">
            <p className="px-2 text-xs font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400">
              Notes
            </p>
            <NotesView id={entry.id} onError={onError} />
          </div>
        ) : null}

        {entry.custom_labels.length > 0 ? (
          <div className="space-y-1">
            <div className="flex items-center justify-between px-2">
              <p className="text-xs font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400">
                Custom fields
              </p>
              <Button
                variant="ghost"
                className="px-2 py-1 text-xs"
                onClick={async () => {
                  if (custom) {
                    setCustom(null);
                    return;
                  }
                  try {
                    const secrets = await api.entryForEdit(entry.id);
                    setCustom(
                      secrets.custom.map((field) => ({
                        label: field.label,
                        value: field.value,
                      })),
                    );
                  } catch (failure) {
                    onError(toFailure(failure).message);
                  }
                }}
              >
                {custom ? "Hide values" : "Show values"}
              </Button>
            </div>
            {entry.custom_labels.map((label, index) => (
              <SecretRow
                key={`${label}-${index}`}
                label={label || "Field"}
                value={custom?.[index]?.value ?? ""}
                masked
                onCopied={onCopied}
                onError={onError}
              />
            ))}
            {custom === null ? (
              <p className="px-2 text-xs text-slate-500 dark:text-slate-400">
                Values stay encrypted until you ask for them.
              </p>
            ) : null}
          </div>
        ) : null}

        {entry.history_len > 0 ? (
          <div className="pt-2">
            <Button
              variant="ghost"
              onClick={async () => {
                try {
                  setHistory(await api.entryHistory(entry.id));
                } catch (failure) {
                  onError(toFailure(failure).message);
                }
              }}
            >
              <ClockIcon className="h-4 w-4" />
              History ({entry.history_len})
            </Button>
          </div>
        ) : null}
      </div>

      {history ? (
        <Modal title="Version history" onClose={() => setHistory(null)}>
          {history.length === 0 ? (
            <p className="text-sm text-slate-500">No previous versions.</p>
          ) : (
            <ul className="space-y-2">
              {history.map((timestamp, index) => (
                <li
                  key={timestamp}
                  className="flex items-center justify-between rounded-lg border border-black/10 px-3 py-2 text-sm dark:border-white/10"
                >
                  <span>{new Date(timestamp).toLocaleString()}</span>
                  <Button
                    onClick={async () => {
                      try {
                        await api.restoreRevision(entry.id, index);
                        setHistory(null);
                        onChanged();
                        onCopied("Previous version restored");
                      } catch (failure) {
                        onError(toFailure(failure).message);
                      }
                    }}
                  >
                    Restore
                  </Button>
                </li>
              ))}
            </ul>
          )}
        </Modal>
      ) : null}

      {confirmDelete ? (
        <Modal
          title="Move to trash?"
          description="Trashed entries are deleted permanently after 30 days."
          onClose={() => setConfirmDelete(false)}
          width="max-w-sm"
        >
          <div className="flex justify-end gap-2">
            <Button onClick={() => setConfirmDelete(false)}>Cancel</Button>
            <Button
              variant="danger"
              onClick={async () => {
                try {
                  await api.deleteEntry(entry.id);
                  setConfirmDelete(false);
                  onChanged();
                  onCopied("Moved to trash");
                } catch (failure) {
                  onError(toFailure(failure).message);
                }
              }}
            >
              Move to trash
            </Button>
          </div>
        </Modal>
      ) : null}
    </div>
  );
}

function NotesView({ id, onError }: { id: string; onError: (message: string) => void }) {
  const [notes, setNotes] = useState<string | null>(null);
  const [revealed, setRevealed] = useState(false);

  useEffect(() => {
    setNotes(null);
    setRevealed(false);
  }, [id]);

  useEffect(() => {
    if (!revealed) return;
    const timer = window.setTimeout(() => setRevealed(false), REVEAL_MS);
    return () => window.clearTimeout(timer);
  }, [revealed]);

  return (
    <div className="rounded-lg border border-black/5 bg-black/[0.02] p-3 dark:border-white/10 dark:bg-white/[0.03]">
      {revealed ? (
        <pre className="whitespace-pre-wrap break-words font-sans text-sm text-slate-800 dark:text-slate-100">
          {notes ?? "Decrypting…"}
        </pre>
      ) : (
        <Button
          variant="ghost"
          onClick={async () => {
            try {
              setNotes(await api.revealField(id, "notes"));
              setRevealed(true);
            } catch (failure) {
              onError(toFailure(failure).message);
            }
          }}
        >
          <EyeIcon className="h-4 w-4" />
          Reveal notes
        </Button>
      )}
      {revealed ? (
        <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
          Hides automatically after 20 seconds.
        </p>
      ) : null}
    </div>
  );
}
