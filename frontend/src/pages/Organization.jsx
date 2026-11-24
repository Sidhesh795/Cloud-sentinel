import { Badge } from "../components/common/Badge.jsx";

export default function Organization({ data }) {
  const org = data.organization;
  return (
    <section className="grid gap-4 max-w-2xl">
      <div className="panel p-5">
        <div className="metric-label">Organization</div>
        <h2 className="mt-1 text-2xl font-bold text-white">{org?.name || "Organization unavailable"}</h2>
        <div className="mt-5 grid gap-3 text-sm">
          <div className="flex justify-between border-b border-sentinel-border/70 pb-2">
            <span className="text-slate-400">Slug</span>
            <span className="font-semibold text-slate-100">{org?.slug || "Unavailable"}</span>
          </div>
          <div className="flex justify-between border-b border-sentinel-border/70 pb-2">
            <span className="text-slate-400">Status</span>
            <Badge className="border-emerald-400/30 bg-emerald-500/10 text-emerald-300">{org?.status || "Unavailable"}</Badge>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-400">Environment</span>
            <Badge className="border-sky-400/30 bg-sky-500/10 text-sky-300">{org?.environment || "Unavailable"}</Badge>
          </div>
        </div>
      </div>
    </section>
  );
}
