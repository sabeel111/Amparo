"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

// Amparo shield mark — a simple, strong SVG (not an emoji). Conveys "guard".
function ShieldMark({ className = "" }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      className={className}
      aria-hidden="true"
    >
      <path
        d="M12 2 3 6v6c0 5 3.8 9.4 9 10 5.2-.6 9-5 9-10V6l-9-4Z"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      <path
        d="M8.5 12.5 11 15l4.5-5"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

const NAV = [
  { href: "/", label: "Overview", icon: "grid" },
  { href: "/projects", label: "Projects", icon: "layers" },
  { href: "/findings", label: "Findings", icon: "alert" },
];

function NavIcon({ name }: { name: string }) {
  const common = "w-4 h-4";
  switch (name) {
    case "grid":
      return (
        <svg viewBox="0 0 24 24" fill="none" className={common} aria-hidden="true">
          <rect x="3" y="3" width="7" height="7" rx="1" stroke="currentColor" strokeWidth="1.5" />
          <rect x="14" y="3" width="7" height="7" rx="1" stroke="currentColor" strokeWidth="1.5" />
          <rect x="3" y="14" width="7" height="7" rx="1" stroke="currentColor" strokeWidth="1.5" />
          <rect x="14" y="14" width="7" height="7" rx="1" stroke="currentColor" strokeWidth="1.5" />
        </svg>
      );
    case "layers":
      return (
        <svg viewBox="0 0 24 24" fill="none" className={common} aria-hidden="true">
          <path d="m12 3 9 5-9 5-9-5 9-5Z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
          <path d="m3 13 9 5 9-5" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
        </svg>
      );
    case "alert":
      return (
        <svg viewBox="0 0 24 24" fill="none" className={common} aria-hidden="true">
          <path d="M12 3 2 20h20L12 3Z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
          <path d="M12 10v4M12 17h.01" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
        </svg>
      );
  }
  return null;
}

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-60 shrink-0 border-r border-border bg-surface flex flex-col h-screen sticky top-0">
      {/* Brand */}
      <div className="px-5 h-16 flex items-center gap-2.5 border-b border-border">
        <ShieldMark className="w-6 h-6 text-foreground" />
        <div className="flex flex-col leading-none">
          <span className="font-semibold tracking-tight text-[15px]">Amparo</span>
          <span className="text-[11px] text-subtle">supply chain security</span>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-0.5">
        {NAV.map((item) => {
          const active =
            item.href === "/"
              ? pathname === "/"
              : pathname.startsWith(item.href);
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
                active
                  ? "bg-surface-2 text-foreground"
                  : "text-muted hover:text-foreground hover:bg-surface-2/60"
              }`}
            >
              <span className={active ? "text-foreground" : "text-subtle"}>
                <NavIcon name={item.icon} />
              </span>
              {item.label}
            </Link>
          );
        })}
      </nav>

      {/* Footer / status */}
      <div className="px-4 py-3 border-t border-border text-[11px] text-subtle">
        <div className="flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500/80" />
          local dev · unauthenticated
        </div>
      </div>
    </aside>
  );
}
