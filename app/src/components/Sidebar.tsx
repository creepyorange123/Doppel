import type { ComponentType, SVGProps } from "react";
import { num } from "../lib/format";
import {
  ActivityIcon,
  AppsIcon,
  BuildingIcon,
  DashboardIcon,
  PanelCloseIcon,
  PanelOpenIcon,
  ScrollIcon,
  SlidersIcon,
} from "./icons";

export type View = "overview" | "companies" | "requests" | "ledger" | "apps" | "settings";

const NAV: { id: View; label: string; icon: ComponentType<SVGProps<SVGSVGElement>> }[] = [
  { id: "overview", label: "Overview", icon: DashboardIcon },
  { id: "companies", label: "Companies", icon: BuildingIcon },
  { id: "requests", label: "Requests", icon: ActivityIcon },
  { id: "ledger", label: "Outgoing calls", icon: ScrollIcon },
  { id: "apps", label: "Apps", icon: AppsIcon },
  { id: "settings", label: "Settings", icon: SlidersIcon },
];

export interface StatusLine {
  text: string;
  state: "ok" | "warn" | "off";
}

export function Sidebar({
  view,
  onNavigate,
  counts,
  collapsed,
  onToggle,
  status,
}: {
  view: View;
  onNavigate: (v: View) => void;
  counts: Partial<Record<View, number>>;
  collapsed: boolean;
  onToggle: () => void;
  status: StatusLine[];
}) {
  const toggleLabel = collapsed ? "Expand sidebar" : "Collapse sidebar";
  return (
    <aside className="sidebar">
      <button className="sidebar-toggle" onClick={onToggle} aria-label={toggleLabel} aria-expanded={!collapsed} title={`${toggleLabel} (Ctrl+\\)`}>
        {collapsed ? <PanelOpenIcon /> : <PanelCloseIcon />}
      </button>
      <nav className="nav" aria-label="Main">
        {NAV.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            className="nav-item"
            aria-current={view === id ? "page" : undefined}
            aria-label={collapsed ? label : undefined}
            title={collapsed ? label : undefined}
            onClick={() => onNavigate(id)}
          >
            <Icon />
            <span className="nav-label">{label}</span>
            {counts[id] !== undefined && <span className="nav-count">{num(counts[id])}</span>}
          </button>
        ))}
      </nav>
      <div className="status">
        {status.map((s) => (
          <span key={s.text} className="status-row" title={s.text}>
            <span className={`dot dot-${s.state}`} />
            <span className="status-text">{s.text}</span>
          </span>
        ))}
      </div>
    </aside>
  );
}
