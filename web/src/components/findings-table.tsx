"use client";

import { useState } from "react";
import type { Finding } from "@/lib/types";
import { isExploitLikely, priorityWeight } from "@/lib/types";
import {
  PriorityBadge,
  ExploitFlag,
  EpssCell,
  CvssCell,
  RemediationCell,
  StatusBadge,
  EcosystemTag,
} from "@/components/badges";

// FindingsTable — the dashboard centerpiece.
//
// Design (from research): neutral rows by default; the ExploitFlag (EPSS>=95 /
// KEV) is the ONE element that carries the red accent. This is the scarce-color
// discipline that defeats "when everything is urgent, nothing is." Sort defaults
// to a composite priority (severity weight, then EPSS), not severity alone.
export function FindingsTable({
  findings,
  onSelect,
  selectedId,
}: {
  findings: Finding[];
  onSelect: (f: Finding) => void;
  selectedId?: number;
}) {
  const [sortKey, setSortKey] = useState<"priority" | "epss" | "cvss" | "package">(
    "priority"
  );

  const sorted = [...findings].sort((a, b) => {
    switch (sortKey) {
      case "epss":
        return b.epss_percentile - a.epss_percentile;
      case "cvss":
        return b.cvss - a.cvss;
      case "package":
        return a.package.localeCompare(b.package);
      case "priority":
      default:
        // Composite: severity weight first, then EPSS — so a medium/KEV-listed
        // issue can outrank a high/low-EPSS one.
        const pw = priorityWeight(b.priority) - priorityWeight(a.priority);
        if (pw !== 0) return pw;
        return b.epss_percentile - a.epss_percentile;
    }
  });

  if (findings.length === 0) {
    return (
      <div className="rounded-lg border border-dashed border-border p-12 text-center">
        <div className="w-10 h-10 mx-auto mb-3 rounded-full bg-surface-2 flex items-center justify-center">
          <svg viewBox="0 0 24 24" fill="none" className="w-5 h-5 text-subtle">
            <path d="m5 13 4 4L19 7" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </div>
        <p className="text-sm text-muted">No findings match these filters.</p>
        <p className="text-xs text-subtle mt-1">This view is clean.</p>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-border overflow-hidden">
      {/* Column headers — clickable for sort, active col indicated subtly. */}
      <div className="grid grid-cols-[minmax(0,1fr)_90px_72px_72px_110px_90px] gap-3 px-4 py-2.5 bg-surface-2/50 text-[11px] font-medium text-subtle uppercase tracking-wide border-b border-border">
        <SortHeader label="Package / Vulnerability" sortKey="package" activeSort={sortKey} onSort={setSortKey} />
        <SortHeader label="Sev" sortKey="priority" activeSort={sortKey} onSort={setSortKey} align="center" />
        <SortHeader label="CVSS" sortKey="cvss" activeSort={sortKey} onSort={setSortKey} align="center" />
        <SortHeader label="EPSS" sortKey="epss" activeSort={sortKey} onSort={setSortKey} align="center" />
        <div className="text-center">Fix</div>
        <div className="text-center">Status</div>
      </div>

      {/* Rows */}
      <div className="max-h-[calc(100vh-260px)] overflow-y-auto">
        {sorted.map((f, i) => {
          const selected = f.id === selectedId;
          const hot = isExploitLikely(f);
          return (
            <button
              key={f.id}
              onClick={() => onSelect(f)}
              className={`w-full text-left grid grid-cols-[minmax(0,1fr)_90px_72px_72px_110px_90px] gap-3 px-4 py-3 items-center transition-colors ${
                i > 0 ? "border-t border-border" : ""
              } ${
                selected
                  ? "bg-surface-2"
                  : "hover:bg-surface-2/40"
              }`}
            >
              {/* Package + vuln — the leftmost, most important cell */}
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-sm truncate">
                    {f.package}
                    <span className="text-subtle">@{f.version}</span>
                  </span>
                  <EcosystemTag ecosystem={f.ecosystem} />
                  {hot && <ExploitFlag finding={f} />}
                </div>
                <div className="text-xs text-muted truncate mt-0.5">
                  <span className="font-mono text-subtle">{f.vuln_id}</span>
                  {f.summary && <span className="text-subtle"> · {f.summary}</span>}
                </div>
              </div>
              {/* Severity */}
              <div className="flex justify-center">
                <PriorityBadge priority={f.priority} />
              </div>
              {/* CVSS */}
              <div className="text-center">
                <CvssCell finding={f} />
              </div>
              {/* EPSS */}
              <div className="text-center">
                <EpssCell finding={f} />
              </div>
              {/* Fix */}
              <div className="text-center">
                <RemediationCell finding={f} />
              </div>
              {/* Status */}
              <div className="flex justify-center">
                <StatusBadge status={f.status} />
              </div>
            </button>
          );
        })}
      </div>

      {/* Footer count */}
      <div className="px-4 py-2 border-t border-border text-xs text-subtle flex items-center justify-between">
        <span>
          {findings.length} finding{findings.length === 1 ? "" : "s"}
        </span>
        <span className="font-mono">sorted by {sortKey}</span>
      </div>
    </div>
  );
}

function SortHeader({
  label,
  sortKey,
  activeSort,
  onSort,
  align = "left",
}: {
  label: string;
  sortKey: "priority" | "epss" | "cvss" | "package";
  activeSort: string;
  onSort: (k: "priority" | "epss" | "cvss" | "package") => void;
  align?: "left" | "center";
}) {
  const isActive = activeSort === sortKey;
  return (
    <button
      onClick={() => onSort(sortKey)}
      className={`flex items-center gap-1 hover:text-foreground transition-colors ${
        align === "center" ? "justify-center" : ""
      } ${isActive ? "text-foreground" : ""}`}
    >
      {label}
      {isActive && <span className="text-subtle">↓</span>}
    </button>
  );
}
