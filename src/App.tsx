import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { listen } from "@tauri-apps/api/event";
import { api, toFailure, type Status } from "./lib/api";
import { Onboarding } from "./components/Onboarding";
import { Unlock } from "./components/Unlock";
import { Vault } from "./components/Vault";
import { Button, Spinner } from "./components/ui";

/**
 * The shell owns exactly one piece of state: the backend `Status`. Every
 * screen (onboarding / unlock / vault) renders from it, and every transition
 * — including locks the Rust side performs on its own (auto-lock, suspend,
 * logoff) — flows through a status refresh. The UI never keeps a shadow copy
 * of lock state that could drift from the process holding the keys.
 */
export default function App() {
  const [status, setStatus] = useState<Status | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const toastTimer = useRef<number | null>(null);

  const notify = useCallback((message: string) => {
    setToast(message);
    if (toastTimer.current !== null) window.clearTimeout(toastTimer.current);
    toastTimer.current = window.setTimeout(() => setToast(null), 4500);
  }, []);

  useEffect(() => {
    return () => {
      if (toastTimer.current !== null) window.clearTimeout(toastTimer.current);
    };
  }, []);

  const refresh = useCallback(async () => {
    try {
      setStatus(await api.status());
      setLoadError(null);
    } catch (failure) {
      setLoadError(toFailure(failure).message);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // The backend emits these whenever the session locks or unlocks outside of
  // a direct UI action; re-reading status keeps the UI truthful.
  useEffect(() => {
    let alive = true;
    const unlisteners: (() => void)[] = [];
    const track = (registration: Promise<() => void>) => {
      registration
        .then((unlisten) => {
          if (alive) {
            unlisteners.push(unlisten);
          } else {
            unlisten();
          }
        })
        .catch(() => {
          // Event bridge unavailable: status polling on actions still works.
        });
    };
    track(
      listen("vault-locked", () => {
        if (alive) void refresh();
      }),
    );
    track(
      listen("vault-unlocked", () => {
        if (alive) void refresh();
      }),
    );
    return () => {
      alive = false;
      for (const unlisten of unlisteners) unlisten();
    };
  }, [refresh]);

  // Theme: "light"/"dark" are explicit; "system" follows Windows and keeps
  // tracking it while the setting is active.
  const theme = status?.theme ?? null;
  useEffect(() => {
    if (theme === null) return;
    const root = document.documentElement;
    if (theme === "dark") {
      root.classList.add("dark");
      return;
    }
    if (theme === "light") {
      root.classList.remove("dark");
      return;
    }
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const sync = () => root.classList.toggle("dark", media.matches);
    sync();
    media.addEventListener("change", sync);
    return () => media.removeEventListener("change", sync);
  }, [theme]);

  const lock = useCallback(async () => {
    try {
      await api.lock();
    } catch (failure) {
      notify(toFailure(failure).message);
    }
    await refresh();
  }, [notify, refresh]);

  let body: ReactNode;
  if (!status) {
    body = loadError ? (
      <div className="flex h-full flex-col items-center justify-center gap-4 p-6">
        <p className="max-w-md text-center text-sm text-rose-600 dark:text-rose-400">
          Cannot reach the Vaultly backend: {loadError}
        </p>
        <Button variant="primary" onClick={() => void refresh()}>
          Retry
        </Button>
      </div>
    ) : (
      <div className="flex h-full items-center justify-center">
        <Spinner label="Starting Vaultly" />
      </div>
    );
  } else if (!status.has_vault) {
    body = <Onboarding onDone={() => void refresh()} />;
  } else if (status.locked) {
    body = (
      <Unlock
        status={status}
        onUnlocked={() => void refresh()}
        onRefresh={() => void refresh()}
      />
    );
  } else {
    body = (
      <Vault
        status={status}
        onLock={() => void lock()}
        onRefreshStatus={() => void refresh()}
        notify={notify}
      />
    );
  }

  return (
    <div className="h-full">
      {body}
      {toast ? (
        <div
          role="status"
          aria-live="polite"
          className="fixed bottom-4 right-4 z-50 max-w-sm rounded-xl border border-black/10 bg-zinc-900 px-4 py-2.5 text-sm text-white shadow-lg dark:border-white/10"
        >
          {toast}
        </div>
      ) : null}
    </div>
  );
}
