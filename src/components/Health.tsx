import { useEffect, useState } from "react";
import { api, toFailure, type EntryMeta, type HealthReport } from "../lib/api";
import { Button } from "./ui";
import { AlertIcon, CheckIcon, ClockIcon, HeartIcon, RefreshIcon } from "./Icons";
import { formatRelative } from "../lib/format";

export function Health({
  entries,
  onSelect,
  onError,
}: {
  entries: EntryMeta[];
  onSelect: (id: string) => void;
  onError: (message: string) => void;
}) {
  const [report, setReport] = useState<HealthReport | null>(null);
  const [busy, setBusy] = useState(false);

  const load = async () => {
    setBusy(true);
    try {
      setReport(await api.healthReport());
    } catch (failure) {
      onError(toFailure(failure).message);
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const titleOf = (id: string) =>
    entries.find((entry) => entry.id === id)?.title ?? "Deleted entry";

  if (!report) {
    return (
      <div className="p-8 text-sm text-slate-500 dark:text-slate-400">
        Analysing passwords locally…
      </div>
    );
  }

  const problems = report.weak.length + report.reused.length + report.old.length;

  return (
    <div className="mx-auto w-full max-w-3xl space-y-6 overflow-y-auto p-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-xl font-semibold text-slate-900 dark:text-white">
            Password health
          </h2>
          <p className="text-sm text-slate-500 dark:text-slate-400">
            Computed on this PC. Passwords are compared as hashes and never leave the vault.
          </p>
        </div>
        <Button onClick={() => void load()} disabled={busy}>
          <RefreshIcon className="h-4 w-4" />
          Re-check
        </Button>
      </div>

      <div
        className={`flex items-center gap-3 rounded-2xl border p-4 ${
          problems === 0
            ? "border-emerald-500/30 bg-emerald-50 dark:bg-emerald-950/30"
            : "border-amber-500/30 bg-amber-50 dark:bg-amber-950/30"
        }`}
      >
        {problems === 0 ? (
          <CheckIcon className="h-6 w-6 text-emerald-600" />
        ) : (
          <AlertIcon className="h-6 w-6 text-amber-600" />
        )}
        <div>
          <p className="text-sm font-semibold text-slate-900 dark:text-white">
            {problems === 0
              ? "No weak, reused or stale passwords"
              : `${problems} issue${problems === 1 ? "" : "s"} found`}
          </p>
          <p className="text-xs text-slate-600 dark:text-slate-400">
            {report.total} active entries analysed.
          </p>
        </div>
      </div>

      <Section
        icon={<HeartIcon className="h-4 w-4" />}
        title="Weak passwords"
        count={report.weak.length}
      >
        {report.weak.map((item) => (
          <Row key={item.id} onClick={() => onSelect(item.id)}>
            <span className="truncate">{titleOf(item.id)}</span>
            <span className="shrink-0 text-xs text-slate-500 dark:text-slate-400">
              score {item.score}/4 · {item.reasons.slice(0, 2).join(", ")}
            </span>
          </Row>
        ))}
      </Section>

      <Section
        icon={<AlertIcon className="h-4 w-4" />}
        title="Reused passwords"
        count={report.reused.length}
      >
        {report.reused.map((group, index) => (
          <Row key={index} onClick={() => onSelect(group.ids[0] ?? "")}>
            <span className="truncate">
              {group.ids.map((id) => titleOf(id)).slice(0, 3).join(", ")}
              {group.ids.length > 3 ? ` +${group.ids.length - 3}` : ""}
            </span>
            <span className="shrink-0 text-xs text-slate-500 dark:text-slate-400">
              used {group.count}×
            </span>
          </Row>
        ))}
      </Section>

      <Section
        icon={<ClockIcon className="h-4 w-4" />}
        title="Old passwords"
        count={report.old.length}
      >
        {report.old.map((item) => (
          <Row key={item.id} onClick={() => onSelect(item.id)}>
            <span className="truncate">{titleOf(item.id)}</span>
            <span className="shrink-0 text-xs text-slate-500 dark:text-slate-400">
              {item.age_days} days · {formatRelative(Date.now() - item.age_days * 86_400_000)}
            </span>
          </Row>
        ))}
      </Section>
    </div>
  );
}

function Section({
  icon,
  title,
  count,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  count: number;
  children: React.ReactNode;
}) {
  if (count === 0) return null;
  return (
    <section className="space-y-2">
      <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-800 dark:text-slate-100">
        {icon}
        {title}
        <span className="rounded-full bg-black/5 px-2 py-0.5 text-xs dark:bg-white/10">
          {count}
        </span>
      </h3>
      <div className="divide-y divide-black/5 overflow-hidden rounded-xl border border-black/10 dark:divide-white/10 dark:border-white/10">
        {children}
      </div>
    </section>
  );
}

function Row({
  children,
  onClick,
}: {
  children: React.ReactNode;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex w-full items-center justify-between gap-3 px-3 py-2 text-left text-sm text-slate-800 hover:bg-black/5 dark:text-slate-100 dark:hover:bg-white/5"
    >
      {children}
    </button>
  );
}
