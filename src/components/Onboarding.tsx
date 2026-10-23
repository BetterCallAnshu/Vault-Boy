import { useMemo, useState } from "react";
import { api, toFailure } from "../lib/api";
import { measure, MIN_MASTER_PASSWORD_LENGTH } from "../lib/strength";
import { Button, Field, StrengthMeter, TextInput, Toggle } from "./ui";
import { AlertIcon, CheckIcon, KeyIcon, LockIcon, ShieldIcon } from "./Icons";

type Step = "intro" | "password" | "recovery";

export function Onboarding({ onDone }: { onDone: () => void }) {
  const [step, setStep] = useState<Step>("intro");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [useRecovery, setUseRecovery] = useState(true);
  const [recoveryKey, setRecoveryKey] = useState<string | null>(null);
  const [savedConfirmed, setSavedConfirmed] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const strength = useMemo(() => (password ? measure(password) : null), [password]);
  const tooShort = password.length < MIN_MASTER_PASSWORD_LENGTH;
  const mismatch = confirm.length > 0 && confirm !== password;
  const weak = strength !== null && strength.score < 3;
  const canCreate = !tooShort && !mismatch && !weak && password.length > 0;

  async function create() {
    if (!canCreate || busy) return;
    setBusy(true);
    setError(null);
    try {
      const key = await api.createVault(password, useRecovery);
      setPassword("");
      setConfirm("");
      if (key) {
        setRecoveryKey(key);
        setStep("recovery");
      } else {
        onDone();
      }
    } catch (failure) {
      setError(toFailure(failure).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex h-full items-center justify-center bg-gradient-to-b from-vault-50 to-white p-6 dark:from-vault-950 dark:to-zinc-950">
      <div className="w-full max-w-xl">
        <div className="mb-6 flex items-center gap-3">
          <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-vault-600 text-white shadow-lg">
            <LockIcon className="h-6 w-6" />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-slate-900 dark:text-white">
              Create your vault
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Everything stays on this PC, encrypted with your master password.
            </p>
          </div>
        </div>

        {step === "intro" ? (
          <div className="space-y-5 rounded-2xl border border-black/10 bg-white/85 p-6 shadow-xl dark:border-white/10 dark:bg-zinc-900/80">
            <div className="space-y-3 text-sm text-slate-700 dark:text-slate-300">
              <p className="flex items-start gap-2">
                <ShieldIcon className="mt-0.5 h-4 w-4 shrink-0 text-vault-600" />
                Vaultly uses Argon2id and XChaCha20-Poly1305. There is no server, no
                account and no telemetry.
              </p>
              <p className="flex items-start gap-2">
                <AlertIcon className="mt-0.5 h-4 w-4 shrink-0 text-amber-500" />
                <strong className="font-semibold">
                  Your master password cannot be recovered.
                </strong>{" "}
                Nobody — including this app — can reset it. If you forget it, the vault is
                gone unless you saved a recovery key.
              </p>
            </div>
            <div className="rounded-xl bg-black/5 p-3 text-xs text-slate-600 dark:bg-white/5 dark:text-slate-400">
              Use a long passphrase (4–6 random words) you have never used elsewhere. A
              password manager's master password is the one password you must remember.
            </div>
            <Button variant="primary" className="w-full" onClick={() => setStep("password")}>
              Continue
            </Button>
          </div>
        ) : null}

        {step === "password" ? (
          <form
            className="space-y-4 rounded-2xl border border-black/10 bg-white/85 p-6 shadow-xl dark:border-white/10 dark:bg-zinc-900/80"
            onSubmit={(event) => {
              event.preventDefault();
              void create();
            }}
          >
            <Field label="Master password">
              <TextInput
                autoFocus
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                autoComplete="new-password"
                spellCheck={false}
                invalid={tooShort && password.length > 0}
              />
            </Field>
            <StrengthMeter strength={strength} password={password} />
            {tooShort && password.length > 0 ? (
              <p className="text-xs text-rose-600 dark:text-rose-400">
                Use at least {MIN_MASTER_PASSWORD_LENGTH} characters.
              </p>
            ) : null}

            <Field label="Confirm master password">
              <TextInput
                type="password"
                value={confirm}
                onChange={(event) => setConfirm(event.target.value)}
                autoComplete="new-password"
                spellCheck={false}
                invalid={mismatch}
              />
            </Field>
            {mismatch ? (
              <p className="text-xs text-rose-600 dark:text-rose-400">
                The two passwords do not match.
              </p>
            ) : null}

            <div className="rounded-xl bg-black/5 px-3 dark:bg-white/5">
              <Toggle
                checked={useRecovery}
                onChange={setUseRecovery}
                label="Create a recovery key"
                description="Shown once after creation. The only way back in if you forget the password."
              />
            </div>

            {error ? (
              <p role="alert" className="text-sm text-rose-600 dark:text-rose-400">
                {error}
              </p>
            ) : null}

            <div className="flex gap-2">
              <Button onClick={() => setStep("intro")} disabled={busy}>
                Back
              </Button>
              <Button type="submit" variant="primary" className="flex-1" disabled={!canCreate || busy}>
                {busy ? "Encrypting vault…" : "Create vault"}
              </Button>
            </div>
            {weak && password.length > 0 ? (
              <p className="text-xs text-amber-600 dark:text-amber-400">
                Choose a stronger password — this one is easy to guess.
              </p>
            ) : null}
          </form>
        ) : null}

        {step === "recovery" && recoveryKey ? (
          <div className="space-y-4 rounded-2xl border border-black/10 bg-white/85 p-6 shadow-xl dark:border-white/10 dark:bg-zinc-900/80">
            <div className="flex items-center gap-2 text-sm font-medium text-slate-800 dark:text-slate-100">
              <KeyIcon className="h-4 w-4 text-vault-600" />
              Save your recovery key now
            </div>
            <p className="text-xs text-slate-600 dark:text-slate-400">
              This key is shown once and is not stored. Anyone with it can open your vault,
              so keep it somewhere physically safe.
            </p>
            <pre className="select-all break-all rounded-xl bg-black/5 p-4 font-mono text-sm text-slate-900 dark:bg-white/5 dark:text-slate-100">
              {recoveryKey}
            </pre>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Write it by hand or store it in a safe. Vaultly will not copy it to the
              clipboard, where other apps could read it.
            </p>
            <label className="flex items-start gap-2 text-sm text-slate-700 dark:text-slate-300">
              <input
                type="checkbox"
                checked={savedConfirmed}
                onChange={(event) => setSavedConfirmed(event.target.checked)}
                className="mt-1 h-4 w-4 rounded border-black/20 accent-vault-600"
              />
              I have written down this recovery key in a safe place.
            </label>
            <Button
              variant="primary"
              className="w-full"
              disabled={!savedConfirmed}
              onClick={onDone}
            >
              <CheckIcon className="h-4 w-4" />
              Open my vault
            </Button>
          </div>
        ) : null}
      </div>
    </div>
  );
}
