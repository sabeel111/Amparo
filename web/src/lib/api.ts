// Thin API client. Points at the Go server (amparo serve, default :8080).
// Override via NEXT_PUBLIC_API_URL if the server runs elsewhere.

const API_BASE =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080/api/v1";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, { cache: "no-store" });
  if (!res.ok) {
    throw new ApiError(res.status, `API ${res.status}: ${await res.text()}`);
  }
  return res.json() as Promise<T>;
}

async function patch<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    throw new ApiError(res.status, `API ${res.status}: ${await res.text()}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  health: () => get<{ status: string }>("/healthz"),
  summary: () =>
    get<{ critical: number; high: number; medium: number; low: number; open: number; fixed: number; total: number; projects: number; exploited: number; direct: number; transitive: number }>("/summary"),
  projects: () => get<{ projects: import("./types").Project[] }>("/projects"),
  project: (name: string) =>
    get<{ id: number; name: string; summary: import("./types").ProjectSummary }>(
      `/projects/${encodeURIComponent(name)}`
    ),
  findings: (
    project: string,
    params: { status?: string; severity?: string; ecosystem?: string; epss?: boolean; q?: string; limit?: number } = {}
  ) => {
    const q = new URLSearchParams();
    if (params.status) q.set("status", params.status);
    if (params.severity) q.set("severity", params.severity);
    if (params.ecosystem) q.set("ecosystem", params.ecosystem);
    if (params.epss) q.set("epss", "1");
    if (params.q) q.set("q", params.q);
    if (params.limit) q.set("limit", String(params.limit));
    const qs = q.toString();
    return get<{ project: string; findings: import("./types").Finding[]; count: number }>(
      `/projects/${encodeURIComponent(project)}/findings${qs ? `?${qs}` : ""}`
    );
  },
  finding: (id: number) =>
    get<import("./types").Finding>(`/findings/${id}`),
  updateFinding: (id: number, status: string) =>
    patch<{ id: number; status: string }>(`/findings/${id}`, { status }),
};
