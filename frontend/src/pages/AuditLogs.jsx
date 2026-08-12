import { Badge } from "../components/common/Badge.jsx";
import { compactDate, decisionTone, titleCase } from "../utils/format.js";

export default function AuditLogs({ events = [] }) {
  const audit = events.filter((event) => event.metadata?.decision || event.event_type?.startsWith("ACCESS") || event.event_type === "MFA_REQUIRED");
  return (
    <section className="panel p-5">
      <div className="mb-4">
        <div className="metric-label">Audit Logs</div>
        <h2 className="mt-1 text-2xl font-bold text-white">Policy Decision History</h2>
      </div>
      <div className="overflow-hidden rounded-lg border border-sentinel-border">
        <table className="w-full text-left text-sm">
          <thead className="bg-white/[0.03] text-xs uppercase tracking-[0.12em] text-slate-400">
            <tr>
              <th className="px-4 py-3">Timestamp</th>
              <th className="px-4 py-3">Resource</th>
              <th className="px-4 py-3">Action</th>
              <th className="px-4 py-3">Risk</th>
              <th className="px-4 py-3">Decision</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-sentinel-border/80">
            {audit.map((event) => (
              <tr key={event.id}>
                <td className="px-4 py-3 text-slate-400">{compactDate(event.timestamp)}</td>
                <td className="px-4 py-3 font-semibold text-white">{event.metadata?.application || "System"}</td>
                <td className="px-4 py-3 text-slate-300">{event.metadata?.action || "EVALUATE"}</td>
                <td className="px-4 py-3 text-slate-300">{event.metadata?.risk_score ?? "--"}</td>
                <td className="px-4 py-3">
                  <Badge className={decisionTone(event.metadata?.decision)}>{titleCase(event.metadata?.decision || event.event_type)}</Badge>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!audit.length && <div className="p-6 text-sm text-slate-400">No policy decisions have been recorded yet.</div>}
      </div>
    </section>
  );
}
