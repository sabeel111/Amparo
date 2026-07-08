// API types — mirror the Go server's JSON contract exactly.
// Keep these in sync with internal/server/server.go findingToDTO().

export type Priority = "critical" | "high" | "medium" | "low";
export type Status = "new" | "triaged" | "fixed" | "suppressed";
export type Actionable = "actionable_now" | "monitor";

export interface Finding {
  id: number;
  package: string;
  version: string;
  ecosystem: string;
  purl: string;
  is_direct: boolean;
  vuln_id: string;
  summary: string;
  aliases: string[];
  cvss: number;
  epss_probability: number;
  epss_percentile: number;
  priority: Priority;
  actionable: Actionable;
  status: Status;
  fixed_versions: string[];
  first_seen: string;
  last_seen: string;
}

export interface Project {
  id: number;
  org: string;
  name: string;
  total_findings: number;
  open_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  last_scanned: string | null;
}

export interface ProjectSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  open: number;
  fixed: number;
  direct: number;
  transitive: number;
  exploited: number;
}

export interface GlobalSummary extends ProjectSummary {
  projects: number;
}

// Derived: EPSS percentile >= 0.95 is the "exploit-likely / act now" signal.
// This is the scarce-color trigger — the ONE thing that gets the red accent.
export function isExploitLikely(f: { epss_percentile: number }): boolean {
  return f.epss_percentile >= 0.95;
}

// Priority weight for sort ordering (critical first).
export function priorityWeight(p: Priority): number {
  switch (p) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    case "low":
      return 1;
  }
  return 0;
}
