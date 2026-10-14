// The browser's view of the broker.
//
// Everything here is read or decide. There is deliberately no call that returns
// a credential, because the broker exposes no such route — the narrowness is
// the product's promise, not a convention of this file.

async function json<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: { 'content-type': 'application/json', ...(init?.headers ?? {}) },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(body.error ?? `request failed with ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export type Check = { label: string; state: 'ok' | 'warn' | 'bad'; detail: string };

export type Status = {
  workspace: string;
  services: number;
  servers: number;
  profiles: string[];
  pending: number;
  checks: Check[];
};

export type Service = {
  name: string;
  host: string;
  kind: string;
  operation: string;
  on_the_wire: string;
  long_lived_on_the_wire: boolean;
  connected: boolean;
  fields: string[];
};

export type PolicyRow = {
  category: string;
  kind: string;
  action: string;
  policy: 'agent' | 'approval' | 'deny';
  summary: string;
  ceiling: 'agent' | 'approval' | 'deny';
};

export type Effect = {
  ID: string;
  Service: string;
  Capability: string;
  Summary: string;
  Args: Record<string, string> | null;
  Submitted: string;
  Expires: string;
  State: 'pending' | 'approved' | 'refused' | 'expired';
  DecidedBy: string;
};

export type AuditEffect = {
  when: string;
  category: string;
  action: string;
  policy: string;
  caller: string;
  credential: string;
  outcome: string;
};

export const api = {
  status: () => json<Status>('/api/status'),
  services: () => json<{ services: Service[] }>('/api/services'),
  policy: () => json<{ rows: PolicyRow[] }>('/api/policy'),
  approvals: () => json<{ effects: Effect[] }>('/api/approvals'),
  audit: () => json<{ effects: AuditEffect[] }>('/api/audit'),

  setPolicy: (category: string, action: string, policy: string) =>
    json('/api/policy', { method: 'POST', body: JSON.stringify({ category, action, policy }) }),
  decide: (id: string, allow: boolean) =>
    json('/api/approvals/decide', { method: 'POST', body: JSON.stringify({ id, allow }) }),
  revoke: (service: string) =>
    json('/api/services/revoke', { method: 'POST', body: JSON.stringify({ service }) }),
};
