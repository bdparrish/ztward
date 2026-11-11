/** Any value that survives a JSON round trip. */
export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

/** A free-form JSON object, e.g. subject/resource attributes or entitlement conditions. */
export type JsonObject = { [key: string]: JsonValue };

export interface Policy {
  id: string;
  name: string;
  description: string;
  language: 'json' | 'opa' | 'xacml';
  policy_content: string;
  effect: 'allow' | 'deny';
  priority: number;
  enabled: boolean;
  created_at: string;
  updated_at: string;
  created_by: string;
  updated_by: string;
}

export interface Entitlement {
  id: string;
  name: string;
  description: string;
  subject_attributes: JsonObject;
  resource_attributes: JsonObject;
  actions: string[];
  conditions: JsonObject;
  enabled: boolean;
  created_at: string;
  updated_at: string;
  created_by: string;
  updated_by: string;
  expires_at?: string;
}

export interface AuditLog {
  id: string;
  entity_id: string;
  entity_type: string;
  action: string;
  actor: string;
  changes: Record<string, unknown>;
  result?: Record<string, unknown>;
  timestamp: string;
  ip_address?: string;
  user_agent?: string;
}
