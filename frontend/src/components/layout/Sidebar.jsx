import { Activity, ClipboardList, Cloud, LayoutDashboard, ShieldAlert, Users, Workflow } from "lucide-react";

const items = [
  ["Overview", LayoutDashboard],
  ["Users", Users],
  ["Security Posture", ShieldAlert],
  ["How It Works", Workflow],
  ["Resources", Cloud],
  ["Incidents", Activity],
  ["Audit Logs", ClipboardList]
];

export default function Sidebar({ current, onNavigate }) {
  return (
    <aside className="flex h-screen w-64 shrink-0 flex-col border-r border-sentinel-border bg-[#071321]/95 px-4 py-5">
      <div className="mb-8">
        <div className="text-lg font-black tracking-[0.18em] text-white">CLOUDSENTINEL</div>
        <div className="mt-1 text-xs uppercase tracking-[0.18em] text-sky-300">Zero Trust Control</div>
      </div>
      <nav className="space-y-1">
        {items.map(([label, Icon]) => (
          <button
            key={label}
            onClick={() => onNavigate(label)}
            className={`focus-ring flex w-full items-center gap-3 rounded-md px-3 py-2.5 text-left text-sm transition ${
              current === label
                ? "bg-sky-400/12 text-sky-100"
                : "text-slate-400 hover:bg-white/5 hover:text-slate-100"
            }`}
          >
            <Icon className="h-4 w-4" />
            {label}
          </button>
        ))}
      </nav>
      <div className="mt-auto rounded-lg border border-emerald-400/20 bg-emerald-500/8 p-3">
        <div className="metric-label">System Status</div>
        <div className="mt-2 flex items-center gap-2 text-sm font-semibold text-emerald-300">
          <span className="h-2 w-2 rounded-full bg-emerald-400 shadow-[0_0_14px_rgba(52,211,153,0.8)]" />
          Operational
        </div>
      </div>
    </aside>
  );
}
