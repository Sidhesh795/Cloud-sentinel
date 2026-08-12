import { ShieldCheck } from "lucide-react";

export default function Header({ applications = [] }) {
  const clouds = new Set(applications.map((item) => item.cloud_provider)).size;
  return (
    <header className="flex h-20 items-center justify-between border-b border-sentinel-border bg-[#081523]/80 px-6">
      <div>
        <h1 className="text-xl font-bold text-white">CloudSentinel</h1>
        <p className="text-sm text-slate-400">Adaptive Zero Trust Control Center</p>
      </div>
      <div className="flex items-center gap-4 text-xs font-bold uppercase tracking-[0.12em] text-slate-300">
        <span className="flex items-center gap-2 rounded-md border border-emerald-400/25 bg-emerald-500/10 px-3 py-2 text-emerald-300">
          <ShieldCheck className="h-4 w-4" />
          System Protected
        </span>
        <span>{clouds || 0} Clouds</span>
        <span>{applications.length} Applications</span>
      </div>
    </header>
  );
}
