// PageHeader — consistent title + optional actions across pages.
export function PageHeader({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-4 mb-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {subtitle && <p className="text-sm text-muted mt-1">{subtitle}</p>}
      </div>
      {children && <div className="flex items-center gap-2">{children}</div>}
    </div>
  );
}

// StatCard — a single metric in the summary grid. Neutral by default; the
// "exploited" count is the one card that carries the accent (scarce color).
export function StatCard({
  label,
  value,
  accent = false,
  hint,
}: {
  label: string;
  value: number | string;
  accent?: boolean;
  hint?: string;
}) {
  return (
    <div
      className={`rounded-lg border bg-surface px-4 py-3.5 ${
        accent ? "border-critical/30 bg-critical/5" : "border-border"
      }`}
    >
      <div className={`text-2xl font-semibold tnum ${accent ? "text-critical" : "text-foreground"}`}>
        {value}
      </div>
      <div className="text-xs text-subtle mt-0.5 flex items-center gap-1.5">
        {accent && (
          <span className="w-1.5 h-1.5 rounded-full bg-critical" />
        )}
        {label}
      </div>
      {hint && <div className="text-[11px] text-subtle mt-1">{hint}</div>}
    </div>
  );
}
