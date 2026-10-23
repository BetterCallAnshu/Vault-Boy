import { invoke } from "@tauri-apps/api/core";

/** Shapes shared with the Rust backend. Keep in sync with `commands.rs`. */

export type EntryKind = "login" | "note" | "card" | "identity";

export type SecretField =
  | "password"
  | "notes"
  | "totp_secret"
  | "card_number"
  | "card_holder"
  | "card_expiry"
  | "card_cvv"
  | "card_pin"
  | "identity_full_name"
  | "identity_email"
  | "identity_phone"
  | "identity_address"
  | "identity_passport"
  | "identity_national_id"
  | "identity_date_of_birth";

export interface EntryMeta {
  id: string;
  kind: EntryKind;
  title: string;
  username: string;
  url: string;
  tags: string[];
  folder: string | null;
  favorite: boolean;
  created_at: number;
  updated_at: number;
  password_updated_at: number | null;
  deleted_at: number | null;
  has_totp: boolean;
  has_notes: boolean;
  has_card: boolean;
  has_identity: boolean;
  custom_labels: string[];
  history_len: number;
}

export interface CustomField {
  label: string;
  value: string;
  secret: boolean;
}

export interface CardSecrets {
  number: string;
  holder: string;
  expiry: string;
  cvv: string;
  pin: string;
}

export interface IdentitySecrets {
  full_name: string;
  email: string;
  phone: string;
  address: string;
  passport: string;
  national_id: string;
  date_of_birth: string;
}

export interface EntrySecrets {
  password: string;
  notes: string;
  totp_secret: string;
  card: CardSecrets | null;
  identity: IdentitySecrets | null;
  custom: CustomField[];
}

export interface EntryDraft {
  kind: EntryKind;
  title: string;
  username: string;
  url: string;
  tags: string[];
  folder: string | null;
  favorite: boolean;
  secrets: EntrySecrets;
}

export interface EntryPatch {
  kind?: EntryKind;
  title?: string;
  username?: string;
  url?: string;
  tags?: string[];
  folder?: string;
  favorite?: boolean;
  secrets?: EntrySecrets;
}

export type Mitigations = {
  dynamic_code_prohibited: boolean;
  strict_handles: boolean;
  extension_points_disabled: boolean;
  image_load_restricted: boolean;
  signature_policy: boolean;
};

export interface Status {
  has_vault: boolean;
  locked: boolean;
  auto_lock_minutes: number;
  capture_protection: boolean;
  clipboard_clear_seconds: number;
  theme: string;
  lock_on_session_events: boolean;
  remote_session: boolean;
  debugger_detected: boolean;
  acl_ok: boolean;
  elevated: boolean;
  mitigations: Mitigations;
  hello_available: boolean;
  rate_limited_ms: number;
  backoff_tampered: boolean;
}

export interface Settings {
  auto_lock_minutes: number;
  capture_protection: boolean;
  clipboard_clear_seconds: number;
  theme: string;
  lock_on_session_events: boolean;
}

export interface GeneratorOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
  exclude_ambiguous: boolean;
  passphrase: boolean;
  words: number;
  separator: string;
  capitalize: boolean;
}

export interface GeneratedSecret {
  value: string;
  entropy_bits: number;
}

export interface TotpCode {
  code: string;
  seconds_remaining: number;
  period: number;
}

export interface HealthReport {
  total: number;
  weak: { id: string; score: number; reasons: string[] }[];
  reused: { ids: string[]; count: number }[];
  old: { id: string; age_days: number }[];
}

export interface ImportSummary {
  imported: number;
  skipped: number;
}

export interface ImportPreview {
  count: number;
  samples: string[];
}

/** Error returned by every command (`ApiError` in Rust). */
export interface ApiFailure {
  code: string;
  message: string;
  retry_after_ms?: number;
}

export function toFailure(error: unknown): ApiFailure {
  if (typeof error === "object" && error !== null && "code" in error) {
    const candidate = error as Partial<ApiFailure>;
    return {
      code: String(candidate.code),
      message: String(candidate.message ?? "The operation failed."),
      ...(typeof candidate.retry_after_ms === "number"
        ? { retry_after_ms: candidate.retry_after_ms }
        : {}),
    };
  }
  return { code: "unknown", message: "The operation failed." };
}

const call = <T>(command: string, args?: Record<string, unknown>) =>
  invoke<T>(command, args);

export const api = {
  status: () => call<Status>("get_status"),
  createVault: (password: string, recovery: boolean) =>
    call<string | null>("create_vault", { password, recovery }),
  unlock: (password: string) => call<void>("unlock", { password }),
  unlockWithRecovery: (recoveryKey: string) =>
    call<void>("unlock_with_recovery", { recoveryKey }),
  lock: () => call<void>("lock"),

  listEntries: () => call<EntryMeta[]>("list_entries"),
  searchEntries: (query: string) => call<string[]>("search_entries", { query }),
  revealField: (id: string, field: SecretField) =>
    call<string>("reveal_field", { id, field }),
  entryForEdit: (id: string) => call<EntrySecrets>("get_entry_for_edit", { id }),
  copyField: (id: string, field: SecretField) =>
    call<{ seconds: number }>("copy_field", { id, field }),
  copyText: (text: string) => call<{ seconds: number }>("copy_text", { text }),
  createEntry: (draft: EntryDraft) => call<string>("create_entry", { draft }),
  updateEntry: (id: string, patch: EntryPatch) =>
    call<void>("update_entry", { id, patch }),
  deleteEntry: (id: string) => call<void>("delete_entry", { id }),
  restoreEntry: (id: string) => call<void>("restore_entry", { id }),
  emptyTrash: () => call<number>("empty_trash"),
  entryHistory: (id: string) => call<number[]>("entry_history", { id }),
  restoreRevision: (id: string, revisionIndex: number) =>
    call<void>("restore_revision", { id, revisionIndex }),

  generatePassword: (options: GeneratorOptions) =>
    call<GeneratedSecret>("generate_password", { options }),
  totpCode: (id: string) => call<TotpCode>("totp_code", { id }),
  healthReport: () => call<HealthReport>("health_report"),
  verifyMasterPassword: (password: string) =>
    call<boolean>("verify_master_password", { password }),
  changeMasterPassword: (currentPassword: string, newPassword: string) =>
    call<void>("change_master_password", { currentPassword, newPassword }),

  previewImport: (path: string) => call<ImportPreview>("preview_import", { request: { path } }),
  importCsv: (path: string) => call<ImportSummary>("import_csv", { request: { path } }),
  exportBackup: (path: string) => call<void>("export_backup", { request: { path } }),
  exportCsv: (path: string, password: string) =>
    call<void>("export_csv", { request: { path }, password }),

  settings: () => call<Settings>("get_settings"),
  updateSettings: (settings: Settings) =>
    call<Settings>("update_settings", { settings }),
};
