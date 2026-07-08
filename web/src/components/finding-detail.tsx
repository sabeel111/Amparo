"use client";

import { useState } from "react";
import { api } from "@/lib/api";
import type { Finding } from "@/lib/types";
import { isExploitLikely } from "@/lib/types";
import {
  PriorityBadge,
  ExploitFlag,
  StatusBadge,
  EcosystemTag,
} from "@/components/badges";

// FindingDetail — the right-side master/detail panel.
// Slides in when a finding is selected. NOT a modal (per research: modals kill
// triage flow). Contains full advisory detail + remediation + triage actions.
export function FindingDetail({
  finding,
  onClose,
  onStatusChange,
}: {
  finding: Finding | null;
  onClose: () => void;
  onStatusChange: (id: number, status: string) => void;
}) {
  const [updating, setUpdating] = useState(false);
  const [dismissReason, setDismissReason] = useState("");

  if (!finding) return null;

  const hot = isExploitLikely(finding);

  async function setStatus(status: string) {
    if (!finding) return;
    setUpdating(true);
    try {
      await api.updateFinding(finding.id, status);
      onStatusChange(finding.id, status);
    } finally {
      setUpdating(false);
    }
  }

  return (
    <>
      {/* Scrim — click to close. Per research: 40-60% opacity for legibility. */}
      <div
        className="fixed inset-0 bg-black/50 z-40"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Panel — slides from the right. */}
      <aside
        className="fixed right-0 top-0 bottom-0 w-full max-w-md bg-surface border-l border-border z-50 flex flex-col"
        role="dialog"
        aria-label="Finding detail"
      >
        {/* Header */}
        <div className="px-5 py-4 border-b border-border flex items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex items-center gap-2 mb-1.5 flex-wrap">
              <PriorityBadge priority={finding.priority} />
              <EcosystemTag ecosystem={finding.ecosystem} />
              {hot && <ExploitFlag finding={finding} />}
            </div>
            <div className="font-mono text-sm break-all">{finding.vuln_id}</div>
          </div>
          <button
            onClick={onClose}
            className="text-subtle hover:text-foreground p-1 -mt-1 -mr-1 transition-colors"
            aria-label="Close detail"
          >
            <svg viewBox="0 0 24 24" fill="none" className="w-5 h-5">
              <path d="m6 6 12 12M18 6 6 18" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
            </svg>
          </button>
        </div>

        {/* Body — scrollable */}
        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-5">
          {/* Summary */}
          {finding.summary && (
            <section>
              <SectionLabel>Summary</SectionLabel>
              <p className="text-sm text-muted leading-relaxed">{finding.summary}</p>
            </section>
          )}

          {/* Affected package */}
          <section>
            <SectionLabel>Affected package</SectionLabel>
            <div className="rounded-md border border-border bg-background p-3 font-mono text-sm space-y-1">
              <div className="flex justify-between gap-4">
                <span className="text-subtle">package</span>
                <span className="truncate">{finding.package}</span>
              </div>
              <div className="flex justify-between gap-4">
                <span className="text-subtle">installed</span>
                <span className="text-high">{finding.version}</span>
              </div>
              <div className="flex justify-between gap-4">
                <span className="text-subtle">scope</span>
                <span>{finding.is_direct ? "direct dependency" : "transitive"}</span>
              </div>
              <div className="flex justify-between gap-4">
                <span className="text-subtle">purl</span>
                <span className="text-subtle text-xs truncate">{finding.purl}</span>
              </div>
            </div>
          </section>

          {/* Risk metrics */}
          <section>
            <SectionLabel>Risk scoring</SectionLabel>
            <div className="grid grid-cols-2 gap-2">
              <Metric
                label="CVSS"
                value={finding.cvss.toFixed(1)}
                hint={`${finding.priority}`}
              />
              <Metric
                label="EPSS %ile"
                value={hot ? `${(finding.epss_percentile * 100).toFixed(0)}%` : `${(finding.epss_percentile * 100).toFixed(1)}%`}
                hint={hot ? "exploit likely" : "exploit probability"}
                accent={hot}
              />
            </div>
          </section>

          {/* Remediation */}
          <section>
            <SectionLabel>Remediation</SectionLabel>
            {finding.fixed_versions && finding.fixed_versions.length > 0 ? (
              <div className="rounded-md border border-emerald-500/20 bg-emerald-500/5 p-3">
                <div className="text-xs text-emerald-400 mb-1.5 flex items-center gap-1.5">
                  <svg viewBox="0 0 24 24" fill="none" className="w-3.5 h-3.5">
                    <path d="m5 13 4 4L19 7" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                  Fix available — upgrade to
                </div>
                <div className="font-mono text-sm">
                  {finding.fixed_versions[0]}
                </div>
                {finding.fixed_versions.length > 1 && (
                  <div className="text-[11px] text-subtle mt-1">
                    other fixed: {finding.fixed_versions.slice(1).join(", ")}
                  </div>
                )}
              </div>
            ) : (
              <div className="text-sm text-subtle italic">
                No fixed version published yet. Monitor the advisory.
              </div>
            )}
          </section>

          {/* Aliases */}
          {finding.aliases && finding.aliases.length > 0 && (
            <section>
              <SectionLabel>Aliases</SectionLabel>
              <div className="flex flex-wrap gap-1.5">
                {finding.aliases.map((a) => (
                  <span
                    key={a}
                    className="font-mono text-xs px-1.5 py-0.5 rounded bg-surface-2 text-muted border border-border"
                  >
                    {a}
                  </span>
                ))}
              </div>
            </section>
          )}

          {/* Lifecycle */}
          <section>
            <SectionLabel>Lifecycle</SectionLabel>
            <div className="flex items-center gap-2 text-xs text-subtle">
              <StatusBadge status={finding.status} />
              <span>first seen {formatRelative(finding.first_seen)}</span>
              <span>·</span>
              <span>seen {formatRelative(finding.last_seen)}</span>
            </div>
          </section>
        </div>

        {/* Triage footer — the actions */}
        <div className="px-5 py-4 border-t border-border space-y-2.5 bg-background">
          {finding.status === "suppressed" && (
            <div className="flex items-center gap-2">
              <input
                type="text"
                placeholder="Dismiss reason (e.g. tolerable risk, not used)"
                value={dismissReason}
                onChange={(e) => setDismissReason(e.target.value)}
                className="flex-1 bg-surface border border-border rounded-md px-3 py-1.5 text-sm placeholder:text-subtle focus:outline-none focus:border-border-strong"
              />
            </div>
          )}
          <div className="flex gap-2">
            <button
              onClick={() => setStatus("triaged")}
              disabled={updating}
              className="flex-1 px-3 py-2 rounded-md text-xs font-medium bg-surface-2 border border-border hover:border-border-strong transition-colors disabled:opacity-50"
            >
              Mark triaged
            </button>
            <button
              onClick={() => setStatus("suppressed")}
              disabled={updating}
              className="flex-1 px-3 py-2 rounded-md text-xs font-medium text-subtle border border-border hover:text-foreground transition-colors disabled:opacity-50"
            >
              Dismiss
            </button>
            {finding.status !== "new" && (
              <button
                onClick={() => setStatus("new")}
                disabled={updating}
                className="px-3 py-2 rounded-md text-xs font-medium text-subtle border border-border hover:text-foreground transition-colors disabled:opacity-50"
              >
                Reopen
              </button>
            )}
          </div>
        </div>
      </aside>
    </>
  );
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="text-[11px] font-medium text-subtle uppercase tracking-wide mb-2">
      {children}
    </div>
  );
}

function Metric({
  label,
  value,
  hint,
  accent = false,
}: {
  label: string;
  value: string;
  hint?: string;
  accent?: boolean;
}) {
  return (
    <div
      className={`rounded-md border p-3 ${
        accent ? "border-critical/30 bg-critical/5" : "border-border bg-background"
      }`}
    >
      <div className={`text-lg font-semibold tnum ${accent ? "text-critical" : "text-foreground"}`}>
        {value}
      </div>
      <div className="text-[11px] text-subtle mt-0.5">
        {label}
        {hint && <span className="text-subtle/70"> · {hint}</span>}
      </div>
    </div>
  );
}

function formatRelative(iso: string): string {
  const d = new Date(iso);
  const diff = Date.now() - d.getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}
