import { Badge } from "../components/common/Badge.jsx";
import { decisionTone, titleCase } from "../utils/format.js";

export default function Resources({ data }) {
  const matrix = data.matrix || [];
  return (
    <div className="space-y-5">
      <div>
        <div className="metric-label">Resources</div>
        <h2 className="mt-1 text-2xl font-bold text-white">Multi-Cloud Resource Inventory</h2>
      </div>
      <div className="grid grid-cols-3 gap-5">
        {["AWS", "AZURE", "GCP"].map((cloud) => (
          <section key={cloud} className="panel p-5">
            <div className="mb-4 flex items-center justify-between">
              <h3 className="text-lg font-black tracking-[0.14em] text-sky-200">{cloud}</h3>
              <span className="text-xs text-slate-400">{matrix.filter((item) => item.cloud === cloud).length} resources</span>
            </div>
            <div className="space-y-3">
              {matrix.filter((item) => item.cloud === cloud).map((item) => (
                <div key={item.application_id} className="panel-soft p-3">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="font-semibold text-white">{item.application}</div>
                      <div className="text-xs text-slate-400">Sensitivity {item.sensitivity} / 100</div>
                    </div>
                    <Badge className={decisionTone(item.decision)}>{titleCase(item.decision)}</Badge>
                  </div>
                </div>
              ))}
            </div>
          </section>
        ))}
      </div>
    </div>
  );
}
