// Severity + priority badges.
//
// DESIGN PHILOSOPHY (from research): color is a SCARCE signal. The severity
// badge uses a subtle tinted dot + text, NOT a full-saturation pill wash — so a
// high-CVSS/low-EPSS issue reads as lower priority than a medium-CVSS/exploited
// one. The loud red accent is reserved for the ExploitFlag (KEV/EPSS>=95).

import type { Priority, Finding } from "@/lib/types";

const PRIORITY_META: Record<
  Priority,
  { label: string; dot: string; text: string }
> = {
  critical: { label: "Critical", dot: "bg-critical", text: "text-critical" },
  high: { label: "High", dot: "bg-high", text: "text-high" },
  medium: { label: "Medium", dot: "bg-medium", text: "text-medium" },
  low: { label: "Low", dot: "bg-low", text: "text-subtle" },
};

export function PriorityBadge({ priority }: { priority: Priority }) {
  const meta = PRIORITY_META[priority];
  if (!meta) return null;
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium whitespace-nowrap">
      <span className={`w-1.5 h-1.5 rounded-full ${meta.dot}`} />
      <span className={meta.text}>{meta.label}</span>
    </span>
  );
}

// ExploitFlag — the ONE element that gets the red accent. Appears inline on a
// row when EPSS >= 95th percentile (exploit likely) — the "act now" signal.
// Per the research, this single scarce signal defeats "when everything is
// urgent, nothing is."
export function ExploitFlag({ finding }: { finding: { epss_percentile: number } }) {
  if (finding.epss_percentile < 0.95) return null;
  return (
    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wide bg-critical/15 text-critical border border-critical/30">
      <svg viewBox="0 0 24 24" fill="none" className="w-3 h-3" aria-hidden="true">
        <path
          d="M13 2 4 14h7l-1 8 9-12h-7l1-8Z"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinejoin="round"
        />
      </svg>
      Exploit likely
    </span>
  );
}

// EPSS display: percentile as the primary number (more decision-useful than
// probability for comparison), muted unless >= 95th.
export function EpssCell({ finding }: { finding: { epss_percentile: number } }) {
  const pct = finding.epss_percentile * 100;
  if (pct <= 0) {
    return <span className="text-subtle text-xs">—</span>;
  }
  const hot = finding.epss_percentile >= 0.95;
  return (
    <span
      className={`tnum text-xs font-mono ${hot ? "text-critical font-semibold" : "text-muted"}`}
      title={`${pct.toFixed(1)}th percentile`}
    >
      {pct.toFixed(0)}
      <span className="text-subtle">%</span>
    </span>
  );
}

// CVSS cell: numeric score, tabular figures. Color follows severity but muted.
export function CvssCell({ finding }: { finding: { cvss: number; priority: Priority } }) {
  const meta = PRIORITY_META[finding.priority];
  const colorClass = meta?.text ?? "text-muted";
  return (
    <span className={`tnum text-xs font-mono font-medium ${colorClass}`}>
      {finding.cvss.toFixed(1)}
    </span>
  );
}

// A compact remediation pill: the upgrade target + bump type.
export function RemediationCell({ finding }: { finding: Finding }) {
  const fixes = finding.fixed_versions;
  if (!fixes || fixes.length === 0) {
    return (
      <span className="text-xs text-subtle italic">no fix</span>
    );
  }
  const target = fixes[0];
  return (
    <span className="inline-flex items-center gap-1 text-xs">
      <span className="font-mono text-muted">{target}</span>
    </span>
  );
}

// Status badge for the lifecycle (new/triaged/fixed/suppressed).
export function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    new: "bg-surface-2 text-muted border-border",
    triaged: "bg-surface-2 text-foreground border-border-strong",
    fixed: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
    suppressed: "bg-surface-2 text-subtle border-border",
  };
  const cls = map[status] ?? map.new;
  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium uppercase tracking-wide border ${cls}`}>
      {status}
    </span>
  );
}

// Ecosystem tag — neutral, just labels the package source.
export function EcosystemTag({ ecosystem }: { ecosystem: string }) {
  return (
    <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono uppercase tracking-wide bg-surface-2 text-subtle border border-border">
      {ecosystem}
    </span>
  );
}
