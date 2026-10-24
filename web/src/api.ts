export type Result = { columns: { name: string; type: string }[]; rows: unknown[][]; truncated: boolean; duration_ms: number };
export type CollectionOptions = {
 exclude_namespaces?: string[]; include_kinds?: string[]; exclude_kinds?: string[];
 qps?: number; burst?: number; parallel?: number; scan_images?: boolean;
 image_src?: string[]; cache_dir?: string; cacert?: string;
 db_repository?: string[]; java_db_repository?: string[];
 skip_db_update?: boolean; skip_java_db_update?: boolean; offline_scan?: boolean;
};
export type Profile = { collection_options?: CollectionOptions; id: string; name: string; kubeconfig: string; context_regex: string; namespaces: string[]; cron: string; enabled: boolean; timeout_seconds: number };
export type Row = Record<string, unknown>;
export async function api<T>(path: string, body?: unknown, method?: string): Promise<T> {
  const response = await fetch(`/api/v1/${path}`, { method: method ?? (body === undefined ? 'GET' : 'POST'), headers: body === undefined ? {} : { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error ?? response.statusText);
  return data as T;
}
export function records(result?: Result): Row[] {
  if (!Array.isArray(result?.rows) || !Array.isArray(result?.columns)) return [];
  return result.rows.map(row => Object.fromEntries(result.columns.map((c, i) => [c.name, row[i]])));
}
export function display(value: unknown): string { return value === null || value === undefined || value === '' ? '—' : typeof value === 'object' ? JSON.stringify(value) : String(value); }
