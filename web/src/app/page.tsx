"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api, ApiError } from "@/lib/api";
import type { Project, GlobalSummary } from "@/lib/types";
import { PageHeader, StatCard } from "@/components/page-header";

export default function OverviewPage() {
  const [summary, setSummary] = useState<GlobalSummary | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([api.summary(), api.projects()])
      .then(([s, p]) => {
        setSummary(s);
        setProjects(p.projects);
      })
      .catch((e) => {
        setError(
          e instanceof ApiError
            ? e.message
            : "Cannot reach the Amparo API. Is `amparo serve` running on :8080?"
        );
      })
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <OverviewSkeleton />;
  if (error) return <ErrorState message={error} />;
  if (!summary) return null;

  const topProjects = [...projects]
    .sort((a, b) => b.open_findings - a.open_findings)
    .slice(0, 6);

  return (
    <div className="p-8 max-w-6xl">
      <PageHeader
        title="Overview"
        subtitle="Continuous software composition analysis across your projects."
      />

      {/* Stat grid — the "exploited" card is the ONE accent (scarce color). */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-3 mb-8">
        <StatCard label="Open findings" value={summary.open} />
        <StatCard label="Projects" value={summary.projects} />
        <StatCard
          label="Exploit likely"
          value={summary.exploited}
          accent={summary.exploited > 0}
          hint="EPSS ≥ 95th percentile"
        />
        <StatCard label="Fixed" value={summary.fixed} />
        <StatCard label="Total tracked" value={summary.total} hint="all-time" />
      </div>

      {/* Severity breakdown bar — subtle, neutral, not a rainbow. */}
      <div className="mb-8">
        <div className="text-xs text-subtle mb-2 uppercase tracking-wide">
          Open findings by severity
        </div>
        <SeverityBar summary={summary} />
      </div>

      {/* Top projects */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-medium text-muted">Priority projects</h2>
          <Link
            href="/projects"
            className="text-xs text-subtle hover:text-foreground transition-colors"
          >
            View all →
          </Link>
        </div>
        {topProjects.length === 0 ? (
          <EmptyProjects />
        ) : (
          <div className="rounded-lg border border-border overflow-hidden">
            {topProjects.map((p, i) => (
              <Link
                key={p.id}
                href={`/projects/${encodeURIComponent(p.name)}`}
                className={`flex items-center justify-between px-4 py-3 hover:bg-surface-2/50 transition-colors ${
                  i > 0 ? "border-t border-border" : ""
                }`}
              >
                <div className="min-w-0">
                  <div className="font-mono text-sm truncate">{p.name}</div>
                  <div className="text-xs text-subtle">{p.org}</div>
                </div>
                <div className="flex items-center gap-4 shrink-0">
                  <SeverityCounts project={p} />
                  <span className="tnum text-sm font-medium w-8 text-right">
                    {p.open_findings}
                  </span>
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function SeverityBar({ summary }: { summary: GlobalSummary }) {
  const segs = [
    { label: "Critical", value: summary.critical, cls: "bg-critical" },
    { label: "High", value: summary.high, cls: "bg-high" },
    { label: "Medium", value: summary.medium, cls: "bg-medium" },
    { label: "Low", value: summary.low, cls: "bg-low/40" },
  ];
  const total = summary.open || 1;
  return (
    <div>
      <div className="flex h-2 rounded-full overflow-hidden bg-surface-2">
        {segs.map((s) =>
          s.value > 0 ? (
            <div
              key={s.label}
              className={s.cls}
              style={{ width: `${(s.value / total) * 100}%` }}
              title={`${s.label}: ${s.value}`}
            />
          ) : null
        )}
      </div>
      <div className="flex flex-wrap gap-x-5 gap-y-1 mt-2.5">
        {segs.map((s) => (
          <div key={s.label} className="flex items-center gap-1.5 text-xs">
            <span className={`w-2 h-2 rounded-full ${s.cls}`} />
            <span className="text-muted">{s.label}</span>
            <span className="tnum text-foreground font-medium">{s.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function SeverityCounts({ project }: { project: Project }) {
  const parts: { label: string; cls: string }[] = [];
  if (project.critical > 0)
    parts.push({ label: `${project.critical}c`, cls: "text-critical" });
  if (project.high > 0)
    parts.push({ label: `${project.high}h`, cls: "text-high" });
  if (project.medium > 0)
    parts.push({ label: `${project.medium}m`, cls: "text-medium" });
  return (
    <div className="flex items-center gap-2 text-xs">
      {parts.length === 0 ? (
        <span className="text-subtle">clean</span>
      ) : (
        parts.map((p, i) => (
          <span key={i} className={`tnum font-medium ${p.cls}`}>
            {p.label}
          </span>
        ))
      )}
    </div>
  );
}

function EmptyProjects() {
  return (
    <div className="rounded-lg border border-dashed border-border p-8 text-center">
      <p className="text-sm text-muted">No projects yet.</p>
      <p className="text-xs text-subtle mt-1">
        Run{" "}
        <code className="font-mono text-muted bg-surface-2 px-1.5 py-0.5 rounded">
          amparo scan --persist ./your-project
        </code>{" "}
        to populate the dashboard.
      </p>
    </div>
  );
}

function ErrorState({ message }: { message: string }) {
  return (
    <div className="p-8 max-w-6xl">
      <PageHeader title="Overview" />
      <div className="rounded-lg border border-critical/30 bg-critical/5 p-6">
        <p className="text-sm text-critical font-medium">
          Cannot load dashboard data
        </p>
        <p className="text-xs text-muted mt-1">{message}</p>
      </div>
    </div>
  );
}

function OverviewSkeleton() {
  return (
    <div className="p-8 max-w-6xl">
      <div className="h-6 w-32 skeleton rounded mb-2" />
      <div className="h-4 w-72 skeleton rounded mb-8" />
      <div className="grid grid-cols-4 gap-3 mb-8">
        {[0, 1, 2, 3].map((i) => (
          <div key={i} className="h-20 skeleton rounded-lg" />
        ))}
      </div>
      <div className="h-2 w-full skeleton rounded-full mb-8" />
      <div className="space-y-2">
        {[0, 1, 2].map((i) => (
          <div key={i} className="h-14 skeleton rounded-lg" />
        ))}
      </div>
    </div>
  );
}
