import { useEffect, useMemo, useState } from "react";
import { open, save } from "@tauri-apps/plugin-dialog";
import { api, toFailure, type Settings, type Status } from "../lib/api";
import { measure, MIN_MASTER_PASSWORD_LENGTH } from "../lib/strength";
import { Button, Field, Modal, StrengthMeter, TextInput, Toggle } from "./ui";
import { AlertIcon, CheckIcon, DownloadIcon, KeyIcon, ShieldIcon, UploadIcon } from "./Icons";

export function SettingsPanel({
  status,
  settings,
  onSettings,
  onChanged,
  onToast,
  onError,
}: {
  status: Status;
  settings: Settings;
  onSettings: (settings: Settings) => void;
  onChanged: () => void;
  onToast: (message: string) => void;
  onError: (message: string) => void;
}) {
  const [changing, setChanging] = useState(false);
  const [importPath, setImportPath] = useState<string | null>(null);
  const [exportingCsv, setExportingCsv] = useState(false);

  async function patch(next: Partial<Settings>) {
    try {
      const saved = await api.updateSettings({ ...settings, ...next });
      onSettings(saved);
    } catch (failure) {
      onError(toFailure(failure).message);
    }
  }

  async function pickImport() {
    const selected = await open({
      multiple: false,
      directory: false,
      title: "Select a CSV export",
      filters: [{ name: "CSV", extensions: ["csv"] }],
    });
    if (typeof selected === "string") setImportPath(selected);
  }

  async function backup() {
    const target = await save({
      title: "Save encrypted backup",
      defaultPath: "vaultly-backup.vlt",
      filters: [{ name: "Vaultly backup", extensions: ["vlt"] }],
    });
    if (!target) return;
    try {
      await api.exportBackup(target);
      onToast("Encrypted backup written");
    } catch (failure) {
      onError(toFailure(failure).message);
    }
  }

  return (
    <div className="mx-auto w-full max-w-3xl space-y-8 overflow-y-auto p-6">
      <div>
        <h2 className="text-xl font-semibold text-slate-900 dark:text-white">Settings</h2>
        <p className="text-sm text-slate-500 dark:text-slate-400">
          Security defaults for this PC. Nothing here is synced anywhere.
        </p>
      </div>

      <section className="space-y-3 rounded-2xl border border-black/10 p-5 dark:border-white/10">
        <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-100">Locking</h3>
        <Field label="Auto-lock after inactivity">
          <select
            value={settings.auto_lock_minutes}
            onChange={(event) => void patch({ auto_lock_minutes: Number(event.target.value) })}
            className="w-full rounded-lg border border-black/10 bg-white/80 px-3 py-2 text-sm dark:border-white/15 dark:bg-black/25 dark:text-slate-100"
          >
            {[1, 2, 5, 10, 15, 30, 60].map((minutes) => (
              <option key={minutes} value={minutes}>
                {minutes} minute{minutes === 1 ? "" : "s"}
              </option>
            ))}
          </select>
        </Field>
        <Toggle
          checked={settings.lock_on_session_events}
          onChange={(value) => void patch({ lock_on_session_events: value })}
          label="Lock on Windows lock, suspend and disconnect"
          description="Also locks when the session ends. Suspending always locks."
        />
        <p className="text-xs text-slate-500 dark:text-slate-400">
          Locking wipes the vault key from memory. Your data stays encrypted on disk.
        </p>
      </section>

      <section className="space-y-3 rounded-2xl border border-black/10 p-5 dark:border-white/10">
        <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-100">
          Screen and clipboard
        </h3>
        <Toggle
          checked={settings.capture_protection}
          onChange={(value) => void patch({ capture_protection: value })}
          label="Exclude this window from screen capture"
          description="Uses SetWindowDisplayAffinity. Blocks screenshots, recording and sharing in most tools, but not a phone camera."
        />
        <Field label="Clear copied secrets after">
          <select
            value={settings.clipboard_clear_seconds}
            onChange={(event) =>
              void patch({ clipboard_clear_seconds: Number(event.target.value) })
            }
            className="w-full rounded-lg border border-black/10 bg-white/80 px-3 py-2 text-sm dark:border-white/15 dark:bg-black/25 dark:text-slate-100"
          >
            {[5, 10, 20, 30, 60].map((seconds) => (
              <option key={seconds} value={seconds}>
                {seconds} seconds
              </option>
            ))}
          </select>
        </Field>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          Copied values are marked to stay out of clipboard history and cloud sync, and are
          cleared only if nothing else has replaced them.
        </p>
      </section>

      <section className="space-y-3 rounded-2xl border border-black/10 p-5 dark:border-white/10">
        <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-100">Appearance</h3>
        <Field label="Theme">
          <select
            value={settings.theme}
            onChange={(event) => void patch({ theme: event.target.value })}
            className="w-full rounded-lg border border-black/10 bg-white/80 px-3 py-2 text-sm dark:border-white/15 dark:bg-black/25 dark:text-slate-100"
          >
            <option value="system">Follow Windows</option>
            <option value="light">Light</option>
            <option value="dark">Dark</option>
          </select>
        </Field>
      </section>

      <section className="space-y-3 rounded-2xl border border-black/10 p-5 dark:border-white/10">
        <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-100">Vault</h3>
        <div className="flex flex-wrap gap-2">
          <Button onClick={() => setChanging(true)}>
            <KeyIcon className="h-4 w-4" />
            Change master password
          </Button>
          <Button onClick={() => void backup()}>
            <DownloadIcon className="h-4 w-4" />
            Encrypted backup
          </Button>
          <Button onClick={() => void pickImport()}>
            <UploadIcon className="h-4 w-4" />
            Import CSV
          </Button>
          <Button variant="danger" onClick={() => setExportingCsv(true)}>
            Export plaintext CSV
          </Button>
        </div>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          An encrypted backup is the vault file itself: it needs the master password (or
          recovery key) to open.
        </p>
      </section>

      <section className="space-y-2 rounded-2xl border border-black/10 p-5 dark:border-white/10">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-800 dark:text-slate-100">
          <ShieldIcon className="h-4 w-4" />
          Protection status
        </h3>
        <StatusRow ok={status.acl_ok} label="Vault folder ACL is user-only" />
        <StatusRow
          ok={status.mitigations.dynamic_code_prohibited}
          label="Dynamic code generation blocked"
        />
        <StatusRow
          ok={status.mitigations.image_load_restricted}
          label="Remote / low-integrity images blocked"
        />
        <StatusRow ok={status.mitigations.strict_handles} label="Strict handle checks" />
        <StatusRow
          ok={status.mitigations.extension_points_disabled}
          label="Legacy extension points disabled"
        />
        <StatusRow
          ok={status.mitigations.signature_policy}
          label="Microsoft-signed images only (release builds)"
        />
        <StatusRow ok={!status.elevated} label="Running as a standard user" />
        <StatusRow ok={!status.remote_session} label="Not a remote session" />
        <StatusRow ok={!status.debugger_detected} label="No debugger detected" />
        <p className="pt-2 text-xs text-slate-500 dark:text-slate-400">
          Windows Hello quick unlock is not available in this build. See docs/SECURITY.md
          for what these protections do and do not cover.
        </p>
      </section>

      {changing ? (
        <ChangePassword
          onClose={() => setChanging(false)}
          onDone={() => {
            setChanging(false);
            onToast("Master password changed");
            onChanged();
          }}
          onError={onError}
        />
      ) : null}

      {importPath ? (
        <ImportDialog
          path={importPath}
          onClose={() => setImportPath(null)}
          onDone={(summary) => {
            setImportPath(null);
            onToast(`Imported ${summary.imported} entries (${summary.skipped} skipped)`);
            onChanged();
          }}
          onError={onError}
        />
      ) : null}

      {exportingCsv ? (
        <PlaintextExport
          onClose={() => setExportingCsv(false)}
          onDone={() => {
            setExportingCsv(false);
            onToast("Plaintext CSV written");
          }}
          onError={onError}
        />
      ) : null}
    </div>
  );
}

function StatusRow({ ok, label }: { ok: boolean; label: string }) {
  return (
    <p className="flex items-center gap-2 text-xs text-slate-600 dark:text-slate-400">
      {ok ? (
        <CheckIcon className="h-3.5 w-3.5 text-emerald-600" />
      ) : (
        <AlertIcon className="h-3.5 w-3.5 text-amber-500" />
      )}
      {label}
    </p>
  );
}

function ChangePassword({
  onClose,
  onDone,
  onError,
}: {
  onClose: () => void;
  onDone: () => void;
  onError: (message: string) => void;
}) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const strength = useMemo(() => (next ? measure(next) : null), [next]);
  const valid =
    next.length >= MIN_MASTER_PASSWORD_LENGTH &&
    next === confirm &&
    (strength?.score ?? 0) >= 3 &&
    current.length > 0;

  return (
    <Modal
      title="Change master password"
      description="Re-wraps the vault key; entry data is not re-encrypted or rewritten in plaintext."
      onClose={onClose}
      width="max-w-md"
    >
      <form
        className="space-y-3"
        onSubmit={async (event) => {
          event.preventDefault();
          if (!valid || busy) return;
          setBusy(true);
          try {
            await api.changeMasterPassword(current, next);
            onDone();
          } catch (failure) {
            onError(toFailure(failure).message);
          } finally {
            setBusy(false);
          }
        }}
      >
        <Field label="Current password">
          <TextInput
            autoFocus
            type="password"
            value={current}
            onChange={(event) => setCurrent(event.target.value)}
            autoComplete="current-password"
          />
        </Field>
        <Field label="New password">
          <TextInput
            type="password"
            value={next}
            onChange={(event) => setNext(event.target.value)}
            autoComplete="new-password"
          />
        </Field>
        <StrengthMeter strength={strength} password={next} />
        <Field label="Confirm new password">
          <TextInput
            type="password"
            value={confirm}
            onChange={(event) => setConfirm(event.target.value)}
            autoComplete="new-password"
            invalid={confirm.length > 0 && confirm !== next}
          />
        </Field>
        <div className="flex justify-end gap-2 pt-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={!valid || busy}>
            {busy ? "Re-wrapping…" : "Change password"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function ImportDialog({
  path,
  onClose,
  onDone,
  onError,
}: {
  path: string;
  onClose: () => void;
  onDone: (summary: { imported: number; skipped: number }) => void;
  onError: (message: string) => void;
}) {
  const [preview, setPreview] = useState<{ count: number; samples: string[] } | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let alive = true;
    api
      .previewImport(path)
      .then((result) => {
        if (alive) setPreview(result);
      })
      .catch((failure) => onError(toFailure(failure).message));
    return () => {
      alive = false;
    };
  }, [path, onError]);

  return (
    <Modal
      title="Import CSV"
      description={path.split(/[\\/]/).pop()}
      onClose={onClose}
      width="max-w-md"
    >
      <div className="space-y-3 text-sm text-slate-600 dark:text-slate-400">
        <p>
          {preview ? `${preview.count} entries detected.` : "Reading file…"}
        </p>
        {preview && preview.samples.length > 0 ? (
          <p className="text-xs">First entries: {preview.samples.join(", ")}</p>
        ) : null}
        <p className="text-xs">
          Importing copies values into your encrypted vault. The source CSV is left
          untouched — delete it yourself afterwards, remembering that SSD overwrite is not
          guaranteed.
        </p>
      </div>
      <div className="mt-4 flex justify-end gap-2">
        <Button onClick={onClose}>Cancel</Button>
        <Button
          variant="primary"
          disabled={!preview || busy}
          onClick={async () => {
            setBusy(true);
            try {
              onDone(await api.importCsv(path));
            } catch (failure) {
              onError(toFailure(failure).message);
            } finally {
              setBusy(false);
            }
          }}
        >
          {busy ? "Importing…" : "Import"}
        </Button>
      </div>
    </Modal>
  );
}

function PlaintextExport({
  onClose,
  onDone,
  onError,
}: {
  onClose: () => void;
  onDone: () => void;
  onError: (message: string) => void;
}) {
  const [password, setPassword] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);
  const [busy, setBusy] = useState(false);

  return (
    <Modal
      title="Export plaintext CSV?"
      description="This writes every password in clear text to disk."
      onClose={onClose}
      width="max-w-md"
    >
      <div className="space-y-3">
        <div className="rounded-xl border border-rose-500/40 bg-rose-50 p-3 text-xs text-rose-800 dark:bg-rose-950/40 dark:text-rose-200">
          Anyone or anything that can read that file — including other apps, backups and
          cloud sync clients — gets your passwords. Vaultly cannot protect it afterwards.
        </div>
        <label className="flex items-start gap-2 text-sm text-slate-700 dark:text-slate-300">
          <input
            type="checkbox"
            checked={acknowledged}
            onChange={(event) => setAcknowledged(event.target.checked)}
            className="mt-1 h-4 w-4 accent-rose-600"
          />
          I understand and still want a plaintext export.
        </label>
        <Field label="Confirm master password">
          <TextInput
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete="current-password"
          />
        </Field>
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="danger"
            disabled={!acknowledged || password.length === 0 || busy}
            onClick={async () => {
              const target = await save({
                title: "Save plaintext CSV",
                defaultPath: "vaultly-export.csv",
                filters: [{ name: "CSV", extensions: ["csv"] }],
              });
              if (!target) return;
              setBusy(true);
              try {
                await api.exportCsv(target, password);
                onDone();
              } catch (failure) {
                onError(toFailure(failure).message);
              } finally {
                setBusy(false);
              }
            }}
          >
            {busy ? "Exporting…" : "Export"}
          </Button>
        </div>
      </div>
    </Modal>
  );
}
