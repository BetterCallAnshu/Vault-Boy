import {
  useEffect,
  useId,
  useRef,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
} from "react";
import { CloseIcon } from "./Icons";
import type { Strength } from "../lib/strength";

type Variant = "primary" | "secondary" | "ghost" | "danger";

const VARIANTS: Record<Variant, string> = {
  primary:
    "bg-vault-600 text-white hover:bg-vault-500 active:bg-vault-700 disabled:bg-vault-600/40 disabled:text-white/70",
  secondary:
    "bg-black/5 text-slate-900 hover:bg-black/10 dark:bg-white/10 dark:text-slate-100 dark:hover:bg-white/15 disabled:opacity-50",
  ghost:
    "text-slate-600 hover:bg-black/5 dark:text-slate-300 dark:hover:bg-white/10 disabled:opacity-50",
  danger:
    "bg-rose-600 text-white hover:bg-rose-500 active:bg-rose-700 disabled:bg-rose-600/40",
};

export function Button({
  variant = "secondary",
  className = "",
  children,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant }) {
  return (
    <button
      type="button"
      className={`inline-flex items-center justify-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium transition-colors disabled:cursor-not-allowed ${VARIANTS[variant]} ${className}`}
      {...props}
    >
      {children}
    </button>
  );
}

export function TextInput({
  className = "",
  invalid,
  ...props
}: InputHTMLAttributes<HTMLInputElement> & { invalid?: boolean }) {
  return (
    <input
      className={`w-full rounded-lg border bg-white/80 px-3 py-2 text-sm text-slate-900 placeholder:text-slate-400 focus:border-vault-500 focus:outline-none dark:bg-black/25 dark:text-slate-100 dark:placeholder:text-slate-500 ${
        invalid
          ? "border-rose-500"
          : "border-black/10 dark:border-white/15"
      } ${className}`}
      {...props}
    />
  );
}

export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <label className="block space-y-1.5">
      <span className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
        {label}
      </span>
      {children}
      {hint ? (
        <span className="block text-xs text-slate-500 dark:text-slate-400">{hint}</span>
      ) : null}
    </label>
  );
}

export function Toggle({
  checked,
  onChange,
  label,
  description,
}: {
  checked: boolean;
  onChange: (value: boolean) => void;
  label: string;
  description?: string;
}) {
  return (
    <div className="flex items-start justify-between gap-4 py-2">
      <div className="min-w-0">
        <p className="text-sm font-medium text-slate-800 dark:text-slate-100">{label}</p>
        {description ? (
          <p className="text-xs text-slate-500 dark:text-slate-400">{description}</p>
        ) : null}
      </div>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={label}
        onClick={() => onChange(!checked)}
        className={`relative mt-1 h-6 w-11 shrink-0 rounded-full border transition-colors ${
          checked
            ? "border-vault-500 bg-vault-600"
            : "border-black/20 bg-black/10 dark:border-white/25 dark:bg-white/15"
        }`}
      >
        <span
          className={`absolute top-0.5 h-4 w-4 rounded-full bg-white shadow transition-[left] ${
            checked ? "left-6" : "left-0.5"
          }`}
        />
      </button>
    </div>
  );
}

export function Modal({
  title,
  description,
  onClose,
  children,
  width = "max-w-xl",
}: {
  title: string;
  description?: string;
  onClose: () => void;
  children: ReactNode;
  width?: string;
}) {
  const headingId = useId();
  const panel = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const first = panel.current?.querySelector<HTMLElement>(
      "input, textarea, select, button",
    );
    first?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.stopPropagation();
        onClose();
      }
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [onClose]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/45 p-6 backdrop-blur-sm"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div
        ref={panel}
        role="dialog"
        aria-modal="true"
        aria-labelledby={headingId}
        className={`mt-10 w-full ${width} rounded-2xl border border-black/10 bg-white p-6 shadow-2xl dark:border-white/15 dark:bg-zinc-900`}
      >
        <div className="mb-4 flex items-start justify-between gap-4">
          <div>
            <h2 id={headingId} className="text-lg font-semibold text-slate-900 dark:text-white">
              {title}
            </h2>
            {description ? (
              <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{description}</p>
            ) : null}
          </div>
          <Button variant="ghost" onClick={onClose} aria-label="Close dialog" className="px-2">
            <CloseIcon className="h-4 w-4" />
          </Button>
        </div>
        {children}
      </div>
    </div>
  );
}

export function StrengthMeter({
  strength,
  password,
}: {
  strength: Strength | null;
  password: string;
}) {
  const bars = [0, 1, 2, 3, 4];
  const colors = [
    "bg-rose-500",
    "bg-orange-500",
    "bg-amber-500",
    "bg-emerald-500",
    "bg-emerald-600",
  ];
  return (
    <div className="space-y-1.5" aria-live="polite">
      <div className="flex gap-1">
        {bars.map((index) => (
          <span
            key={index}
            className={`h-1.5 flex-1 rounded-full ${
              strength && strength.score >= index
                ? (colors[strength.score] ?? "bg-rose-500")
                : "bg-black/10 dark:bg-white/15"
            }`}
          />
        ))}
      </div>
      <p className="text-xs text-slate-500 dark:text-slate-400">
        {password.length === 0
          ? "Use a long, unique passphrase you have not used anywhere else."
          : `${strength?.label ?? "Very weak"}${
              strength?.warning ? ` — ${strength.warning}` : ""
            }`}
      </p>
    </div>
  );
}

export function Spinner({ label = "Working" }: { label?: string }) {
  return (
    <span className="inline-flex items-center gap-2 text-sm text-slate-500 dark:text-slate-400">
      <span
        className="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent"
        aria-hidden="true"
      />
      <span className="sr-only">{label}</span>
    </span>
  );
}
