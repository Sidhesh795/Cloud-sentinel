import { Badge } from "../components/common/Badge.jsx";
import { riskTone } from "../utils/format.js";

export default function Users({ data, onSelectUser }) {
  return (
    <section className="panel p-5">
      <div className="mb-4">
        <div className="metric-label">Users</div>
        <h2 className="mt-1 text-2xl font-bold text-white">Monitored Identities</h2>
      </div>
      <div className="grid grid-cols-2 gap-4">
        {data.userSummaries.map((item) => (
          <button key={item.user.id} onClick={() => onSelectUser(item.user.id)} className="panel-soft p-4 text-left transition hover:bg-sky-400/5">
            <div className="flex items-start justify-between">
              <div>
                <div className="font-bold text-white">{item.user.display_name}</div>
                <div className="text-sm text-slate-400">{item.user.username} / {item.user.role}</div>
              </div>
              <Badge className={riskTone(item.risk?.risk_level)}>{item.risk?.risk_score ?? "--"} {item.risk?.risk_level}</Badge>
            </div>
            <div className="mt-3 text-xs text-slate-500">Device: {item.posture?.devices?.[0]?.device_id || item.user.device_id}</div>
          </button>
        ))}
      </div>
    </section>
  );
}
