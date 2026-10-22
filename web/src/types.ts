export type SessionUser = {
  id: string;
  email: string;
  display_name: string;
  role: string;
  status: string;
  organization_id: string;
};

export type Service = {
  id: string;
  name: string;
  category: string;
  url: string;
  description: string;
  unclear: boolean;
  logo: string;
  logo_bg: string;
  logo_fg: string;
  notes: string;
  created_at: string;
};

export type Account = {
  id: string;
  service_id: string;
  label: string;
  login_hint: string;
  card_label: string;
  notes: string;
  vault_id: string | null;
  vault_item_id: string | null;
  position: number;
};

export type Subscription = {
  id: string;
  service_id: string;
  account_id: string | null;
  billing_cycle: string;
  custom_interval_days: number | null;
  renewal_date: string;
  cost: string;
  currency: string;
  days: number;
  due_level: string;
  monthly: string;
};

export type WorkspaceData = {
  organization: { id: string; name: string; recovery_ready: boolean };
  services: Service[];
  accounts: Account[];
  subscriptions: Subscription[];
  alerts: { id: string; service_id: string; name: string; days_before: number; due_on: string; cost: string; currency: string }[];
  summary: { services: number; accounts: number; unclear: number; overdue: number; due_soon: number; monthly: Record<string, string> };
};

export type PublicKey = {
  user_id: string;
  display_name: string;
  email: string;
  user_status: string;
  key_status: string;
  fingerprint: string;
  public_key: string;
};

export type VaultInfo = {
  id: string;
  name: string;
  key_version: number;
  rotation_required: boolean;
  role: string;
  initialized: boolean;
};

export const categories: [string, string, string][] = [
  ["all", "All services", "▦"],
  ["infra", "Infrastructure", "▤"],
  ["domains", "Domains and protection", "◇"],
  ["tools", "Work tools", "◫"],
  ["comms", "Communications", "✉"],
  ["partners", "Games and partners", "◈"],
  ["payments", "Payments", "▱"],
  ["other", "Other", "⋯"],
];

export const currencies = ["USD", "EUR", "RUB", "GBP", "USDT"];

export const cycles: [string, string][] = [
  ["monthly", "Monthly"],
  ["quarterly", "Quarterly"],
  ["annual", "Annual"],
  ["custom", "Custom interval"],
];
