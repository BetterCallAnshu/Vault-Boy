import type { EntryKind } from "./api";

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

export function formatDate(ms: number): string {
  return new Date(ms).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

export function formatRelative(ms: number, now = Date.now()): string {
  const delta = Math.max(0, now - ms);
  if (delta < MINUTE) return "just now";
  if (delta < HOUR) return `${Math.floor(delta / MINUTE)} min ago`;
  if (delta < DAY) return `${Math.floor(delta / HOUR)} h ago`;
  if (delta < 30 * DAY) return `${Math.floor(delta / DAY)} d ago`;
  return formatDate(ms);
}

export function daysUntil(ms: number, now = Date.now()): number {
  return Math.max(0, Math.ceil((ms - now) / DAY));
}

export function kindLabel(kind: EntryKind): string {
  switch (kind) {
    case "login":
      return "Login";
    case "note":
      return "Secure note";
    case "card":
      return "Card";
    case "identity":
      return "Identity";
  }
}

export function hostOf(url: string): string {
  if (!url) return "";
  try {
    const parsed = new URL(url.includes("://") ? url : `https://${url}`);
    return parsed.hostname.replace(/^www\./, "");
  } catch {
    return url.replace(/^https?:\/\//, "").split("/")[0] ?? "";
  }
}

export function initials(title: string): string {
  const words = title.trim().split(/\s+/).filter(Boolean);
  if (words.length === 0) return "?";
  if (words.length === 1) return (words[0] ?? "?").slice(0, 2).toUpperCase();
  return `${(words[0] ?? "").charAt(0)}${(words[1] ?? "").charAt(0)}`.toUpperCase();
}

/** Deterministic accent per entry so the list has colour without images. */
export function accentFor(seed: string): string {
  const palette = [
    "bg-vault-500",
    "bg-emerald-500",
    "bg-amber-500",
    "bg-rose-500",
    "bg-sky-500",
    "bg-violet-500",
  ];
  let hash = 0;
  for (let index = 0; index < seed.length; index += 1) {
    hash = (hash * 31 + seed.charCodeAt(index)) >>> 0;
  }
  return palette[hash % palette.length] ?? "bg-vault-500";
}
