"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api, ApiError } from "@/lib/api";
import type { Project } from "@/lib/types";
import { PageHeader } from "@/components/page-header";

// Cross-project findings view. Lists projects with open findings so the user
// can drill in. (A full unified findings table across projects would need a
// new API endpoint; for now we route through projects.)
export default function FindingsPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .projects()
      .then((p) =>
        setProjects(
          p.projects
            .filter((proj) => proj.open_findings > 0)
            .sort((a, b) => b.open_findings - a.open_findings)
        )
      )
      .catch((e) =>
        setError(e instanceof ApiError ? e.message : "Cannot reach the Amparo API.")
      )
      .finally(() => setLoading(false));
  }, []);

  const totalOpen = projects.reduce((s, p) => s + p.open_findings, 0);

  return (
    <div className="p-8 max-w-4xl">
      <PageHeader
        title="Findings"
        subtitle={`${totalOpen} open finding${totalOpen === 1 ? "" : "s"} across ${projects.length} project${projects.length === 1 ? "" : "s"}.`}
      />

      {loading ? (
        <div className="space-y-2">
          {[0, 1, 2].map((i) => (
            <div key={i} className="h-14 skeleton rounded-lg" />
          ))}
        </div>
      ) : error ? (
        <div className="rounded-lg border border-critical/30 bg-critical/5 p-4 text-sm text-muted">
          {error}
        </div>
      ) : projects.length === 0 ? (
        <div className="rounded-lg border border-dashed border-border p-12 text-center">
          <div className="w-10 h-10 mx-auto mb-3 rounded-full bg-surface-2 flex items-center justify-center">
            <svg viewBox="0 0 24 24" fill="none" className="w-5 h-5 text-subtle">
              <path d="m5 13 4 4L19 7" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </div>
          <p className="text-sm text-muted">No open findings.</p>
          <p className="text-xs text-subtle mt-1">All projects are clean.</p>
        </div>
      ) : (
        <div className="rounded-lg border border-border overflow-hidden">
          {projects.map((p, i) => (
            <Link
              key={p.id}
              href={`/projects/${encodeURIComponent(p.name)}`}
              className={`flex items-center justify-between px-4 py-3.5 hover:bg-surface-2/40 transition-colors ${
                i > 0 ? "border-t border-border" : ""
              }`}
            >
              <div className="min-w-0">
                <div className="font-mono text-sm">{p.name}</div>
                <div className="text-xs text-subtle flex items-center gap-2 mt-0.5">
                  {p.critical > 0 && (
                    <span className="text-critical font-medium">{p.critical} critical</span>
                  )}
                  {p.high > 0 && (
                    <span className="text-high">{p.high} high</span>
                  )}
                  {p.critical + p.high === 0 && (
                    <span>{p.medium} medium · {p.low} low</span>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <span className="tnum text-lg font-semibold">{p.open_findings}</span>
                <svg viewBox="0 0 24 24" fill="none" className="w-4 h-4 text-subtle">
                  <path d="m9 6 6 6-6 6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
