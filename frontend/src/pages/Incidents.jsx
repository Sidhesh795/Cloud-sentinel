import { compactDate, severityTone, titleCase } from "../utils/format.js";

const groups = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export default function Incidents({ events = [] }) {
  return (
    <div className="space-y-5">
      <div>
        <div className="metric-label">Incidents</div>
        <h2 className="mt-1 text-2xl font-bold text-white">Security Event Center</h2>
      </div>
      <div className="grid grid-cols-5 gap-4">
        {groups.map((group) => (
          <section key={group} className="panel p-4">
            <div className={`mb-3 text-sm font-bold ${severityTone(group)}`}>{group}</div>
            <div className="space-y-3">
              {events.filter((event) => event.severity === group).slice(0, 8).map((event) => (
                <div key={event.id} className="rounded-md border border-sentinel-border bg-white/[0.02] p-3">
                  <div className="text-xs text-slate-500">{compactDate(event.timestamp)}</div>
                  <div className="mt-1 text-sm font-semibold text-slate-100">{titleCase(event.event_type)}</div>
                  <div className="mt-1 text-xs text-slate-400">{event.description}</div>
                </div>
              ))}
              {!events.some((event) => event.severity === group) && <div className="text-xs text-slate-500">No events</div>}
            </div>
          </section>
        ))}
      </div>
    </div>
  );
}
