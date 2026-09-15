import { Badge } from "../components/common/Badge.jsx";

export default function Organization({ data }) {
  const org = data.organization;
  const mongo = data.mongoHealth;
  return (
    <section className="grid gap-4 lg:grid-cols-[1fr_1fr]">
      <div className="panel p-5">
        <div className="metric-label">Organization</div>
        <h2 className="mt-1 text-2xl font-bold text-white">{org?.name || "CloudSentinel Demo"}</h2>
        <div className="mt-5 grid gap-3 text-sm">
          <div className="flex justify-between border-b border-sentinel-border/70 pb-2">
            <span className="text-slate-400">Slug</span>
            <span className="font-semibold text-slate-100">{org?.slug || "cloudsentinel-demo"}</span>
          </div>
          <div className="flex justify-between border-b border-sentinel-border/70 pb-2">
            <span className="text-slate-400">Status</span>
            <Badge className="border-emerald-400/30 bg-emerald-500/10 text-emerald-300">{org?.status || "ACTIVE"}</Badge>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-400">Environment</span>
            <Badge className="border-sky-400/30 bg-sky-500/10 text-sky-300">{org?.environment || "DEMO"}</Badge>
          </div>
        </div>
      </div>
      <div className="panel p-5">
        <div className="metric-label">Data Layer</div>
        <h2 className="mt-1 text-2xl font-bold text-white">Persistence Foundation</h2>
        <div className="mt-5 grid gap-3 text-sm">
          <div className="flex justify-between border-b border-sentinel-border/70 pb-2">
            <span className="text-slate-400">SQLite Demo</span>
            <Badge className="border-emerald-400/30 bg-emerald-500/10 text-emerald-300">ACTIVE</Badge>
          </div>
          <div className="flex justify-between border-b border-sentinel-border/70 pb-2">
            <span className="text-slate-400">MongoDB Atlas</span>
            <Badge className={mongo?.status === "healthy" ? "border-emerald-400/30 bg-emerald-500/10 text-emerald-300" : "border-amber-400/30 bg-amber-500/10 text-amber-300"}>
              {mongo?.status || "unavailable"}
            </Badge>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-400">Database</span>
            <span className="font-semibold text-slate-100">{mongo?.database || "cloudsentinel"}</span>
          </div>
        </div>
      </div>
    </section>
  );
}
