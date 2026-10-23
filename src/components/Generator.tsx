import { useCallback, useEffect, useRef, useState } from "react";
import { api, toFailure, type GeneratorOptions } from "../lib/api";
import { Button, TextInput, Toggle } from "./ui";
import { CopyIcon, RefreshIcon, SparklesIcon } from "./Icons";

const DEFAULTS: GeneratorOptions = {
  length: 20,
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
  exclude_ambiguous: true,
  passphrase: false,
  words: 6,
  separator: "-",
  capitalize: false,
};

export function Generator({
  onUse,
  onCopied,
  onError,
}: {
  onUse?: (value: string) => void;
  onCopied?: (seconds: number) => void;
  onError?: (message: string) => void;
}) {
  const [options, setOptions] = useState<GeneratorOptions>(DEFAULTS);
  const [value, setValue] = useState("");
  const [entropy, setEntropy] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const requestId = useRef(0);

  const regenerate = useCallback(
    async (next: GeneratorOptions) => {
      const id = ++requestId.current;
      try {
        const generated = await api.generatePassword(next);
        if (id !== requestId.current) return;
        setValue(generated.value);
        setEntropy(generated.entropy_bits);
        setError(null);
        onError?.("");
      } catch (failure) {
        if (id !== requestId.current) return;
        const message = toFailure(failure).message;
        setError(message);
        onError?.(message);
      }
    },
    [onError],
  );

  useEffect(() => {
    void regenerate(options);
  }, [options, regenerate]);

  const update = <K extends keyof GeneratorOptions>(key: K, next: GeneratorOptions[K]) =>
    setOptions((current) => ({ ...current, [key]: next }));

  async function copy() {
    try {
      const result = await api.copyText(value);
      onCopied?.(result.seconds);
    } catch (failure) {
      onError?.(toFailure(failure).message);
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        <TextInput
          readOnly
          value={value}
          aria-label="Generated password"
          spellCheck={false}
          className="font-mono text-base"
          onFocus={(event) => event.currentTarget.select()}
        />
        <Button onClick={() => void regenerate(options)} aria-label="Generate another">
          <RefreshIcon className="h-4 w-4" />
        </Button>
      </div>
      <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
        <span>
          {options.passphrase
            ? `${options.words} words · ~${Math.round(entropy)} bits`
            : `${options.length} characters · ~${Math.round(entropy)} bits of entropy`}
        </span>
        <span className="flex items-center gap-1">
          <SparklesIcon className="h-3.5 w-3.5" />
          {entropy >= 90 ? "Very strong" : entropy >= 70 ? "Strong" : "Adequate"}
        </span>
      </div>

      <div className="flex flex-wrap gap-2">
        <Button variant="primary" onClick={() => void copy()} disabled={!value}>
          <CopyIcon className="h-4 w-4" />
          Copy
        </Button>
        {onUse ? (
          <Button onClick={() => onUse(value)} disabled={!value}>
            Use this password
          </Button>
        ) : null}
        <Button variant="ghost" onClick={() => setOptions(DEFAULTS)}>
          Reset
        </Button>
      </div>

      <div className="rounded-xl bg-black/5 px-3 py-1 dark:bg-white/5">
        <Toggle
          checked={options.passphrase}
          onChange={(next) => update("passphrase", next)}
          label="Passphrase mode"
          description="Words are easier to type on a phone or TV."
        />
      </div>

      {options.passphrase ? (
        <div className="space-y-3">
          <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
            Words: {options.words}
            <input
              type="range"
              min={4}
              max={16}
              value={options.words}
              onChange={(event) => update("words", Number(event.target.value))}
              className="mt-2 w-full accent-vault-600"
            />
          </label>
          <div className="flex items-center gap-3">
            <span className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
              Separator
            </span>
            <TextInput
              value={options.separator}
              maxLength={3}
              onChange={(event) => update("separator", event.target.value)}
              className="w-20 text-center"
            />
            <span className="flex-1">
              <Toggle
                checked={options.capitalize}
                onChange={(next) => update("capitalize", next)}
                label="Capitalise"
              />
            </span>
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
            Length: {options.length}
            <input
              type="range"
              min={8}
              max={64}
              value={options.length}
              onChange={(event) => update("length", Number(event.target.value))}
              className="mt-2 w-full accent-vault-600"
            />
          </label>
          <div className="grid grid-cols-2 gap-x-4">
            <Toggle
              checked={options.lowercase}
              onChange={(next) => update("lowercase", next)}
              label="a-z"
            />
            <Toggle
              checked={options.uppercase}
              onChange={(next) => update("uppercase", next)}
              label="A-Z"
            />
            <Toggle
              checked={options.digits}
              onChange={(next) => update("digits", next)}
              label="0-9"
            />
            <Toggle
              checked={options.symbols}
              onChange={(next) => update("symbols", next)}
              label="!@#$"
            />
          </div>
          <Toggle
            checked={options.exclude_ambiguous}
            onChange={(next) => update("exclude_ambiguous", next)}
            label="Exclude look-alike characters"
            description="Removes I, l, 1, O, 0 and similar."
          />
        </div>
      )}

      {error ? (
        <p role="alert" className="text-sm text-rose-600 dark:text-rose-400">
          {error}
        </p>
      ) : null}
    </div>
  );
}
