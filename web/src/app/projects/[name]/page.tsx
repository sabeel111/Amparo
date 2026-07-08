"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams } from "next/navigation";
import { api, ApiError } from "@/lib/api";
import type { Finding, ProjectSummary } from "@/lib/types";
import { PageHeader, StatCard } from "@/components/page-header";
import { FindingsTable } from "@/components/findings-table";
import { FindingDetail } from "@/components/finding-detail";

type SeverityFilter = "" | "critical" | "high" | "medium" | "low";
type StatusTab = "open" | "fixed" | "all";

export default function ProjectDetailPage() {
  const params = useParams<{ name: string }>();
  const name = decodeURIComponent(params.name);

  const [summary, setSummary] = useState<ProjectSummary | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [statusTab, setStatusTab] = useState<StatusTab>("open");
  const [severity, setSeverity] = useState<SeverityFilter>("");
  const [ecosystem, setEcosystem] = useState<string>("");
  const [onlyExploit, setOnlyExploit] = useState(false);
  const [query, setQuery] = useState("");

  // Selected finding (detail panel)
  const [selected, setSelected] = useState<Finding | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const statusParam = statusTab === "open" ? "open" : statusTab === "fixed" ? "fixed" : "";
      const [s, f] = await Promise.all([
        api.project(name),
        api.findings(name, {
          status: statusParam,
          severity: severity || undefined,
          ecosystem: ecosystem || undefined,
          epss: onlyExploit || undefined,
          q: query || undefined,
          limit: 500,
        }),
      ]);
      setSummary(s.summary);
      setFindings(f.findings);
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Cannot load project data.");
    } finally {
      setLoading(false);
    }
  }, [name, statusTab, severity, ecosystem, onlyExploit, query]);

  useEffect(() => {
    load();
  }, [load]);

  function handleStatusChange(id: number, status: string) {
    // Optimistically update the finding in the list + selected.
    setFindings((prev) =>
      prev.map((f) => (f.id === id ? { ...f, status: status as Finding["status"] } : f))
    );
    if (selected?.id === id) {
      setSelected((prev) => (prev ? { ...prev, status: status as Finding["status"] } : null));
    }
  }

  return (
    <div className="p-8 max-w-7xl">
      <PageHeader
        title={name}
        subtitle={
          summary
            ? `${summary.open} open · ${summary.fixed} fixed · ${summary.exploited} exploit-likely`
            : "Loading…"
        }
      />

      {/* Stat strip — the "exploited" card carries the accent. */}
      {summary && (
        <div className="grid grid-cols-3 md:grid-cols-6 gap-3 mb-6">
          <StatCard label="Open" value={summary.open} />
          <StatCard
            label="Exploit likely"
            value={summary.exploited}
            accent={summary.exploited > 0}
          />
          <StatCard label="Critical" value={summary.critical} />
          <StatCard label="High" value={summary.high} />
          <StatCard label="Direct" value={summary.direct} hint="affected" />
          <StatCard label="Fixed" value={summary.fixed} />
        </div>
      )}

      {/* Filter bar */}
      <div className="flex items-center gap-2 mb-4 flex-wrap">
        {/* Open/Closed tabs */}
        <div className="flex rounded-md border border-border overflow-hidden">
          {(["open", "fixed", "all"] as StatusTab[]).map((t) => (
            <button
              key={t}
              onClick={() => setStatusTab(t)}
              className={`px-3 py-1.5 text-xs font-medium capitalize transition-colors ${
                statusTab === t
                  ? "bg-surface-2 text-foreground"
                  : "text-subtle hover:text-muted bg-surface"
              } ${t !== "open" ? "border-l border-border" : ""}`}
            >
              {t}
            </button>
          ))}
        </div>

        <Divider />

        {/* Severity filter */}
        <Select
          value={severity}
          onChange={(v) => setSeverity(v as SeverityFilter)}
          options={[
            { value: "", label: "All severities" },
            { value: "critical", label: "Critical" },
            { value: "high", label: "High" },
            { value: "medium", label: "Medium" },
            { value: "low", label: "Low" },
          ]}
        />

        {/* Ecosystem filter */}
        <Select
          value={ecosystem}
          onChange={setEcosystem}
          options={[
            { value: "", label: "All ecosystems" },
            { value: "npm", label: "npm" },
            { value: "pypi", label: "PyPI" },
            { value: "go", label: "Go" },
            { value: "cargo", label: "Cargo" },
          ]}
        />

        {/* The "act now" filter — EPSS>=95 / KEV. Accent only when active. */}
        <button
          onClick={() => setOnlyExploit((v) => !v)}
          className={`px-3 py-1.5 rounded-md text-xs font-medium border transition-colors ${
            onlyExploit
              ? "bg-critical/10 text-critical border-critical/30"
              : "bg-surface text-subtle border-border hover:text-muted"
          }`}
        >
          ⚡ Exploit likely
        </button>

        {/* Search */}
        <div className="relative ml-auto">
          <svg
            viewBox="0 0 24 24"
            fill="none"
            className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-subtle"
          >
            <circle cx="11" cy="11" r="7" stroke="currentColor" strokeWidth="1.5" />
            <path d="m20 20-3.5-3.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
          </svg>
          <input
            type="text"
            placeholder="Filter package or CVE…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-56 bg-surface border border-border rounded-md pl-8 pr-3 py-1.5 text-xs placeholder:text-subtle focus:outline-none focus:border-border-strong font-mono"
          />
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="rounded-lg border border-critical/30 bg-critical/5 p-4 text-sm text-muted mb-4">
          {error}
        </div>
      )}

      {/* Table */}
      {loading ? (
        <div className="rounded-lg border border-border overflow-hidden">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className={`h-16 skeleton ${i > 0 ? "border-t border-border" : ""}`} />
          ))}
        </div>
      ) : (
        <FindingsTable
          findings={findings}
          onSelect={setSelected}
          selectedId={selected?.id}
        />
      )}

      {/* Detail panel */}
      <FindingDetail
        finding={selected}
        onClose={() => setSelected(null)}
        onStatusChange={handleStatusChange}
      />
    </div>
  );
}

function Divider() {
  return <div className="w-px h-6 bg-border mx-1" />;
}

function Select({
  value,
  onChange,
  options,
}: {
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="bg-surface border border-border rounded-md px-2.5 py-1.5 text-xs text-muted focus:outline-none focus:border-border-strong cursor-pointer"
    >
      {options.map((o) => (
        <option key={o.value} value={o.value} className="bg-surface text-foreground">
          {o.label}
        </option>
      ))}
    </select>
  );
}
