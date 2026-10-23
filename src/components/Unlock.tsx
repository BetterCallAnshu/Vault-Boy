import { useEffect, useMemo, useState } from "react";
import { api, toFailure, type Status } from "../lib/api";
import { Button, Field, TextInput } from "./ui";
import { AlertIcon, KeyIcon, LockIcon, ShieldIcon } from "./Icons";

export function Unlock({
  status,
  onUnlocked,
  onRefresh,
}: {
  status: Status;
  onUnlocked: () => void;
  onRefresh: () => void;
}) {
  const [password, setPassword] = useState("");
  const [recoveryKey, setRecoveryKey] = useState("");
  const [useRecovery, setUseRecovery] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [waitMs, setWaitMs] = useState(status.rate_limited_ms);

  useEffect(() => {
    if (waitMs <= 0) return;
    const timer = window.setInterval(() => {
      setWaitMs((current) => Math.max(0, current - 250));
    }, 250);
    return () => window.clearInterval(timer);
  }, [waitMs]);

  const warnings = useMemo(() => {
    const items: string[] = [];
    if (status.backoff_tampered) {
      items.push("The failed-unlock record was modified. Treat this machine as untrusted.");
    }
    if (status.remote_session) {
      items.push("You are in a remote session. Screen and clipboard protections are weaker.");
    }
    if (status.debugger_detected) {
      items.push("A debugger appears to be attached to Vaultly.");
    }
    return items;
  }, [status]);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      if (useRecovery) {
        await api.unlockWithRecovery(recoveryKey);
      } else {
        await api.unlock(password);
      }
      setPassword("");
      setRecoveryKey("");
      onUnlocked();
    } catch (failure) {
      const parsed = toFailure(failure);
      setError(parsed.message);
      if (parsed.retry_after_ms) setWaitMs(parsed.retry_after_ms);
      onRefresh();
    } finally {
      setBusy(false);
    }
  }

  const blocked = waitMs > 0;

  return (
    <div className="flex h-full items-center justify-center bg-gradient-to-b from-vault-50 to-white p-6 dark:from-vault-950 dark:to-zinc-950">
      <div className="w-full max-w-md">
        <div className="mb-8 flex items-center gap-3">
          <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-vault-600 text-white shadow-lg">
            <LockIcon className="h-6 w-6" />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-slate-900 dark:text-white">Vaultly</h1>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Unlock your local vault
            </p>
          </div>
        </div>

        <form
          onSubmit={submit}
          className="space-y-4 rounded-2xl border border-black/10 bg-white/85 p-6 shadow-xl backdrop-blur dark:border-white/10 dark:bg-zinc-900/80"
        >
          {useRecovery ? (
            <Field label="Recovery key">
              <TextInput
                autoFocus
                value={recoveryKey}
                onChange={(event) => setRecoveryKey(event.target.value)}
                placeholder="XXXX-XXXX-XXXX-…"
                spellCheck={false}
                autoComplete="off"
                aria-describedby="recovery-help"
              />
            </Field>
          ) : (
            <Field label="Master password" hint="Unlocking derives the key locally. Nothing is sent anywhere.">
              <TextInput
                autoFocus
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                autoComplete="current-password"
                spellCheck={false}
              />
            </Field>
          )}

          {error ? (
            <p role="alert" className="flex items-start gap-2 text-sm text-rose-600 dark:text-rose-400">
              <AlertIcon className="mt-0.5 h-4 w-4 shrink-0" />
              {error}
            </p>
          ) : null}

          {blocked ? (
            <p className="text-sm text-amber-600 dark:text-amber-400" role="status">
              Too many attempts. Try again in {Math.ceil(waitMs / 1000)}s.
            </p>
          ) : null}

          <Button
            type="submit"
            variant="primary"
            className="w-full"
            disabled={busy || blocked || (useRecovery ? recoveryKey.length < 8 : password.length === 0)}
          >
            {busy ? "Unlocking…" : "Unlock"}
          </Button>

          <button
            type="button"
            className="w-full text-center text-xs font-medium text-vault-700 hover:underline dark:text-vault-300"
            onClick={() => {
              setUseRecovery((current) => !current);
              setError(null);
            }}
          >
            {useRecovery ? "Use master password instead" : "Use a recovery key"}
          </button>
        </form>

        {warnings.length > 0 ? (
          <ul className="mt-4 space-y-2 rounded-xl border border-amber-400/40 bg-amber-50 p-3 text-xs text-amber-900 dark:bg-amber-950/40 dark:text-amber-200">
            {warnings.map((warning) => (
              <li key={warning} className="flex gap-2">
                <ShieldIcon className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                {warning}
              </li>
            ))}
          </ul>
        ) : null}

        <p className="mt-6 flex items-center justify-center gap-2 text-xs text-slate-500 dark:text-slate-400">
          <KeyIcon className="h-3.5 w-3.5" />
          Offline only · no account · no telemetry
        </p>
      </div>
    </div>
  );
}
