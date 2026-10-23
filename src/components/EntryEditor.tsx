import { useEffect, useState } from "react";
import {
  api,
  toFailure,
  type CardSecrets,
  type CustomField,
  type EntryKind,
  type EntryMeta,
  type EntrySecrets,
  type IdentitySecrets,
} from "../lib/api";
import { Button, Field, Modal, TextInput } from "./ui";
import { EyeIcon, EyeOffIcon, PlusIcon, SparklesIcon, TrashIcon } from "./Icons";
import { Generator } from "./Generator";

const EMPTY_CARD: CardSecrets = { number: "", holder: "", expiry: "", cvv: "", pin: "" };
const EMPTY_IDENTITY: IdentitySecrets = {
  full_name: "",
  email: "",
  phone: "",
  address: "",
  passport: "",
  national_id: "",
  date_of_birth: "",
};
const EMPTY_SECRETS: EntrySecrets = {
  password: "",
  notes: "",
  totp_secret: "",
  card: null,
  identity: null,
  custom: [],
};

const KINDS: { value: EntryKind; label: string }[] = [
  { value: "login", label: "Login" },
  { value: "note", label: "Secure note" },
  { value: "card", label: "Card" },
  { value: "identity", label: "Identity" },
];

export function EntryEditor({
  entry,
  onClose,
  onSaved,
  onCopied,
}: {
  entry?: EntryMeta | undefined;
  onClose: () => void;
  onSaved: () => void;
  onCopied: (message: string) => void;
}) {
  const editing = entry !== undefined;
  const [kind, setKind] = useState<EntryKind>(entry?.kind ?? "login");
  const [title, setTitle] = useState(entry?.title ?? "");
  const [username, setUsername] = useState(entry?.username ?? "");
  const [url, setUrl] = useState(entry?.url ?? "");
  const [tags, setTags] = useState((entry?.tags ?? []).join(", "));
  const [folder, setFolder] = useState(entry?.folder ?? "");
  const [favorite, setFavorite] = useState(entry?.favorite ?? false);
  const [secrets, setSecrets] = useState<EntrySecrets>(EMPTY_SECRETS);
  const [reveal, setReveal] = useState(false);
  const [showGenerator, setShowGenerator] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(editing);

  useEffect(() => {
    if (!entry) return;
    let alive = true;
    api
      .entryForEdit(entry.id)
      .then((loaded) => {
        if (!alive) return;
        setSecrets({
          ...loaded,
          card: loaded.card ?? null,
          identity: loaded.identity ?? null,
        });
      })
      .catch((failure) => {
        if (alive) setError(toFailure(failure).message);
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [entry]);

  useEffect(() => {
    if (!reveal) return;
    const timer = window.setTimeout(() => setReveal(false), 15_000);
    return () => window.clearTimeout(timer);
  }, [reveal]);

  const setSecret = <K extends keyof EntrySecrets>(key: K, value: EntrySecrets[K]) =>
    setSecrets((current) => ({ ...current, [key]: value }));

  const card = secrets.card ?? EMPTY_CARD;
  const identity = secrets.identity ?? EMPTY_IDENTITY;

  const setCard = (patch: Partial<CardSecrets>) =>
    setSecret("card", { ...card, ...patch });
  const setIdentity = (patch: Partial<IdentitySecrets>) =>
    setSecret("identity", { ...identity, ...patch });

  function updateCustom(index: number, patch: Partial<CustomField>) {
    setSecrets((current) => ({
      ...current,
      custom: current.custom.map((field, position) =>
        position === index ? { ...field, ...patch } : field,
      ),
    }));
  }

  async function save(event: React.FormEvent) {
    event.preventDefault();
    if (busy) return;
    if (title.trim().length === 0) {
      setError("Give this entry a title.");
      return;
    }
    setBusy(true);
    setError(null);

    const cleanTags = tags
      .split(",")
      .map((tag) => tag.trim())
      .filter((tag) => tag.length > 0)
      .slice(0, 64);

    const payload: EntrySecrets = {
      ...secrets,
      card: kind === "card" ? card : null,
      identity: kind === "identity" ? identity : null,
    };

    try {
      if (entry) {
        await api.updateEntry(entry.id, {
          kind,
          title: title.trim(),
          username,
          url,
          tags: cleanTags,
          folder: folder.trim(),
          favorite,
          secrets: payload,
        });
      } else {
        await api.createEntry({
          kind,
          title: title.trim(),
          username,
          url,
          tags: cleanTags,
          folder: folder.trim() || null,
          favorite,
          secrets: payload,
        });
      }
      onSaved();
      onClose();
    } catch (failure) {
      setError(toFailure(failure).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      title={editing ? "Edit entry" : "New entry"}
      onClose={onClose}
      width="max-w-2xl"
    >
      {loading ? (
        <p className="py-8 text-center text-sm text-slate-500">Decrypting entry…</p>
      ) : (
        <form className="space-y-4" onSubmit={save}>
          <div className="grid grid-cols-[1fr_170px] gap-3">
            <Field label="Title">
              <TextInput
                value={title}
                onChange={(event) => setTitle(event.target.value)}
                maxLength={512}
                required
              />
            </Field>
            <Field label="Type">
              <select
                value={kind}
                onChange={(event) => setKind(event.target.value as EntryKind)}
                className="w-full rounded-lg border border-black/10 bg-white/80 px-3 py-2 text-sm text-slate-900 focus:border-vault-500 focus:outline-none dark:border-white/15 dark:bg-black/25 dark:text-slate-100"
              >
                {KINDS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </Field>
          </div>

          {kind !== "note" ? (
            <div className="grid grid-cols-2 gap-3">
              <Field label="Username / e-mail">
                <TextInput
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  autoComplete="off"
                  spellCheck={false}
                />
              </Field>
              <Field label="Website">
                <TextInput
                  value={url}
                  onChange={(event) => setUrl(event.target.value)}
                  placeholder="example.com"
                  autoComplete="off"
                  spellCheck={false}
                />
              </Field>
            </div>
          ) : null}

          {kind === "login" || kind === "note" ? (
            <Field label={kind === "note" ? "Note" : "Password"}>
              {kind === "login" ? (
                <div className="flex gap-2">
                  <div className="relative flex-1">
                    <TextInput
                      type={reveal ? "text" : "password"}
                      value={secrets.password}
                      onChange={(event) => setSecret("password", event.target.value)}
                      autoComplete="new-password"
                      spellCheck={false}
                      className="pr-10 font-mono"
                    />
                    <button
                      type="button"
                      onClick={() => setReveal((current) => !current)}
                      aria-label={reveal ? "Hide password" : "Show password"}
                      className="absolute inset-y-0 right-2 my-auto h-7 w-7 rounded-md text-slate-500 hover:bg-black/5 dark:text-slate-400 dark:hover:bg-white/10"
                    >
                      {reveal ? (
                        <EyeOffIcon className="mx-auto h-4 w-4" />
                      ) : (
                        <EyeIcon className="mx-auto h-4 w-4" />
                      )}
                    </button>
                  </div>
                  <Button onClick={() => setShowGenerator(true)}>
                    <SparklesIcon className="h-4 w-4" />
                    Generate
                  </Button>
                </div>
              ) : (
                <textarea
                  value={secrets.notes}
                  onChange={(event) => setSecret("notes", event.target.value)}
                  rows={6}
                  className="w-full rounded-lg border border-black/10 bg-white/80 px-3 py-2 text-sm dark:border-white/15 dark:bg-black/25 dark:text-slate-100"
                />
              )}
            </Field>
          ) : null}

          {kind === "login" ? (
            <div className="grid grid-cols-2 gap-3">
              <Field label="TOTP secret" hint="Base32 secret or otpauth:// URI.">
                <TextInput
                  value={secrets.totp_secret}
                  onChange={(event) => setSecret("totp_secret", event.target.value)}
                  autoComplete="off"
                  spellCheck={false}
                  className="font-mono"
                />
              </Field>
              <Field label="Notes">
                <textarea
                  value={secrets.notes}
                  onChange={(event) => setSecret("notes", event.target.value)}
                  rows={2}
                  className="w-full rounded-lg border border-black/10 bg-white/80 px-3 py-2 text-sm dark:border-white/15 dark:bg-black/25 dark:text-slate-100"
                />
              </Field>
            </div>
          ) : null}

          {kind === "card" ? (
            <div className="grid grid-cols-2 gap-3">
              <Field label="Card number">
                <TextInput
                  value={card.number}
                  onChange={(event) => setCard({ number: event.target.value })}
                  autoComplete="off"
                  spellCheck={false}
                  className="font-mono"
                />
              </Field>
              <Field label="Cardholder">
                <TextInput
                  value={card.holder}
                  onChange={(event) => setCard({ holder: event.target.value })}
                  autoComplete="off"
                />
              </Field>
              <Field label="Expiry">
                <TextInput
                  value={card.expiry}
                  onChange={(event) => setCard({ expiry: event.target.value })}
                  placeholder="MM/YY"
                  autoComplete="off"
                />
              </Field>
              <div className="grid grid-cols-2 gap-3">
                <Field label="CVV">
                  <TextInput
                    value={card.cvv}
                    onChange={(event) => setCard({ cvv: event.target.value })}
                    autoComplete="off"
                    className="font-mono"
                  />
                </Field>
                <Field label="PIN">
                  <TextInput
                    type="password"
                    value={card.pin}
                    onChange={(event) => setCard({ pin: event.target.value })}
                    autoComplete="off"
                    className="font-mono"
                  />
                </Field>
              </div>
            </div>
          ) : null}

          {kind === "identity" ? (
            <div className="grid grid-cols-2 gap-3">
              <Field label="Full name">
                <TextInput
                  value={identity.full_name}
                  onChange={(event) => setIdentity({ full_name: event.target.value })}
                  autoComplete="off"
                />
              </Field>
              <Field label="E-mail">
                <TextInput
                  value={identity.email}
                  onChange={(event) => setIdentity({ email: event.target.value })}
                  autoComplete="off"
                />
              </Field>
              <Field label="Phone">
                <TextInput
                  value={identity.phone}
                  onChange={(event) => setIdentity({ phone: event.target.value })}
                  autoComplete="off"
                />
              </Field>
              <Field label="Date of birth">
                <TextInput
                  value={identity.date_of_birth}
                  onChange={(event) => setIdentity({ date_of_birth: event.target.value })}
                  placeholder="YYYY-MM-DD"
                  autoComplete="off"
                />
              </Field>
              <Field label="Passport">
                <TextInput
                  value={identity.passport}
                  onChange={(event) => setIdentity({ passport: event.target.value })}
                  autoComplete="off"
                />
              </Field>
              <Field label="National ID">
                <TextInput
                  value={identity.national_id}
                  onChange={(event) => setIdentity({ national_id: event.target.value })}
                  autoComplete="off"
                />
              </Field>
              <div className="col-span-2">
                <Field label="Address">
                  <textarea
                    value={identity.address}
                    onChange={(event) => setIdentity({ address: event.target.value })}
                    rows={2}
                    className="w-full rounded-lg border border-black/10 bg-white/80 px-3 py-2 text-sm dark:border-white/15 dark:bg-black/25 dark:text-slate-100"
                  />
                </Field>
              </div>
            </div>
          ) : null}

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
                Custom fields
              </span>
              <Button
                onClick={() =>
                  setSecrets((current) => ({
                    ...current,
                    custom: [...current.custom, { label: "", value: "", secret: true }],
                  }))
                }
              >
                <PlusIcon className="h-4 w-4" />
                Add field
              </Button>
            </div>
            {secrets.custom.map((field, index) => (
              <div key={index} className="flex items-center gap-2">
                <TextInput
                  value={field.label}
                  placeholder="Label"
                  onChange={(event) => updateCustom(index, { label: event.target.value })}
                  className="w-40"
                  maxLength={256}
                />
                <TextInput
                  type={field.secret ? "password" : "text"}
                  value={field.value}
                  placeholder="Value"
                  onChange={(event) => updateCustom(index, { value: event.target.value })}
                  className="flex-1 font-mono"
                  autoComplete="off"
                />
                <label className="flex items-center gap-1 text-xs text-slate-500 dark:text-slate-400">
                  <input
                    type="checkbox"
                    checked={field.secret}
                    onChange={(event) =>
                      updateCustom(index, { secret: event.target.checked })
                    }
                    className="h-4 w-4 accent-vault-600"
                  />
                  Secret
                </label>
                <Button
                  variant="ghost"
                  aria-label="Remove field"
                  onClick={() =>
                    setSecrets((current) => ({
                      ...current,
                      custom: current.custom.filter((_, position) => position !== index),
                    }))
                  }
                >
                  <TrashIcon className="h-4 w-4" />
                </Button>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-2 gap-3">
            <Field label="Tags" hint="Comma separated.">
              <TextInput
                value={tags}
                onChange={(event) => setTags(event.target.value)}
                autoComplete="off"
              />
            </Field>
            <Field label="Folder">
              <TextInput
                value={folder}
                onChange={(event) => setFolder(event.target.value)}
                list="vault-folders"
                autoComplete="off"
              />
            </Field>
          </div>

          <label className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300">
            <input
              type="checkbox"
              checked={favorite}
              onChange={(event) => setFavorite(event.target.checked)}
              className="h-4 w-4 accent-vault-600"
            />
            Mark as favourite
          </label>

          {error ? (
            <p role="alert" className="text-sm text-rose-600 dark:text-rose-400">
              {error}
            </p>
          ) : null}

          <div className="flex justify-end gap-2 pt-2">
            <Button onClick={onClose} disabled={busy}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" disabled={busy}>
              {busy ? "Saving…" : editing ? "Save changes" : "Add entry"}
            </Button>
          </div>
        </form>
      )}

      {showGenerator ? (
        <Modal title="Generate a password" onClose={() => setShowGenerator(false)}>
          <Generator
            onUse={(value) => {
              setSecret("password", value);
              setShowGenerator(false);
            }}
            onCopied={(seconds) => onCopied(`Password copied · clears in ${seconds}s`)}
            onError={(message) => {
              if (message) onCopied(message);
            }}
          />
        </Modal>
      ) : null}
    </Modal>
  );
}
