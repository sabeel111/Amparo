"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api, ApiError } from "@/lib/api";
import type { Project } from "@/lib/types";
import { PageHeader } from "@/components/page-header";

export default function ProjectsPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .projects()
      .then((p) => setProjects(p.projects))
      .catch((e) =>
        setError(
          e instanceof ApiError ? e.message : "Cannot reach the Amparo API."
        )
      )
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="p-8 max-w-6xl">
      <PageHeader
        title="Projects"
        subtitle={`${projects.length} project${projects.length === 1 ? "" : "s"} under monitoring.`}
      />

      {loading ? (
        <TableSkeleton rows={4} />
      ) : error ? (
        <div className="rounded-lg border border-critical/30 bg-critical/5 p-4 text-sm text-muted">
          {error}
        </div>
      ) : projects.length === 0 ? (
        <div className="rounded-lg border border-dashed border-border p-12 text-center">
          <p className="text-sm text-muted">No projects scanned yet.</p>
        </div>
      ) : (
        <div className="rounded-lg border border-border overflow-hidden">
          {/* Header */}
          <div className="grid grid-cols-[1fr_120px_140px_80px] gap-4 px-4 py-2.5 bg-surface-2/50 text-[11px] font-medium text-subtle uppercase tracking-wide border-b border-border">
            <div>Project</div>
            <div className="text-center">Severity</div>
            <div className="text-right">Last scanned</div>
            <div className="text-right">Open</div>
          </div>
          {/* Rows */}
          {projects.map((p, i) => (
            <Link
              key={p.id}
              href={`/projects/${encodeURIComponent(p.name)}`}
              className={`grid grid-cols-[1fr_120px_140px_80px] gap-4 px-4 py-3 items-center hover:bg-surface-2/40 transition-colors ${
                i > 0 ? "border-t border-border" : ""
              }`}
            >
              <div className="min-w-0">
                <div className="font-mono text-sm truncate">{p.name}</div>
                <div className="text-xs text-subtle">{p.org}</div>
              </div>
              <div className="flex items-center gap-1.5 justify-center text-xs">
                {p.critical > 0 && (
                  <span className="tnum font-medium text-critical">{p.critical}c</span>
                )}
                {p.high > 0 && (
                  <span className="tnum font-medium text-high">{p.high}h</span>
                )}
                {p.medium > 0 && (
                  <span className="tnum font-medium text-medium">{p.medium}m</span>
                )}
                {p.critical + p.high + p.medium === 0 && (
                  <span className="text-subtle">—</span>
                )}
              </div>
              <div className="text-right text-xs text-subtle font-mono">
                {p.last_scanned ? formatRelative(p.last_scanned) : "—"}
              </div>
              <div className="text-right">
                <span className="tnum text-sm font-medium">{p.open_findings}</span>
              </div>
            </Link>
          ))}
        </div>
      )}
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
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

function TableSkeleton({ rows }: { rows: number }) {
  return (
    <div className="rounded-lg border border-border overflow-hidden">
      {Array.from({ length: rows }).map((_, i) => (
        <div
          key={i}
          className={`h-14 skeleton ${i > 0 ? "border-t border-border" : ""}`}
        />
      ))}
    </div>
  );
}
