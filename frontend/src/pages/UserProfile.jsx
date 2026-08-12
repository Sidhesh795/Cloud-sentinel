import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import AccessMatrix from "../components/security/AccessMatrix.jsx";
import PostureTags from "../components/security/PostureTags.jsx";
import RiskGauge from "../components/security/RiskGauge.jsx";

export default function UserProfile({ data, onDecisionSelect }) {
  const latest = data.telemetry?.[0];
  const baseline = data.telemetry?.[data.telemetry.length - 1] || latest;
  const bars = latest ? [
    { name: "Requests", baseline: baseline?.requests_per_minute || 0, current: latest.requests_per_minute },
    { name: "Data MB", baseline: baseline?.data_download_mb || 0, current: latest.data_download_mb },
    { name: "Failed", baseline: baseline?.failed_logins || 0, current: latest.failed_logins },
    { name: "Frequency", baseline: baseline?.access_frequency || 0, current: latest.access_frequency }
  ] : [];

  return (
    <div className="grid grid-cols-[0.95fr_1.35fr] gap-5">
      <div className="space-y-5">
        <section className="panel p-5">
          <div className="metric-label">User Security Profile</div>
          <h2 className="mt-2 text-2xl font-bold text-white">{data.selected?.display_name}</h2>
          <p className="text-sm text-slate-400">{data.selected?.username} / {data.selected?.role}</p>
          <div className="mt-5"><RiskGauge score={data.risk?.risk_score || 0} level={data.risk?.risk_level || "LOW"} /></div>
          <div className="mt-5 grid grid-cols-2 gap-3 text-sm">
            <Info label="Device" value={data.posture?.devices?.[0]?.device_id || "Unknown"} />
            <Info label="Location" value={latest?.location || data.posture?.devices?.[0]?.location || "Unknown"} />
            <Info label="OS" value={data.posture?.devices?.[0]?.os_version || "Unknown"} />
            <Info label="Session" value="Monitored" />
          </div>
        </section>
        <section className="panel p-5">
          <div className="metric-label mb-3">Security Posture</div>
          <PostureTags tags={data.posture?.security_tags || []} />
        </section>
      </div>

      <div className="space-y-5">
        <section className="panel p-5">
          <div className="metric-label mb-3">AI-Assisted Risk Assessment</div>
          <div className="grid grid-cols-4 gap-3">
            {Object.entries(data.risk?.components || {}).map(([name, value]) => (
              <div key={name} className="panel-soft p-3">
                <div className="text-xs uppercase tracking-[0.12em] text-slate-400">{name} Risk</div>
                <div className="mt-2 h-2 rounded-full bg-slate-800">
                  <div className="h-2 rounded-full bg-sky-400" style={{ width: `${Math.min(value, 100)}%` }} />
                </div>
                <div className="mt-2 text-lg font-bold">{value}</div>
              </div>
            ))}
          </div>
          <div className="mt-5">
            <div className="metric-label mb-2">Why Is This User Risky?</div>
            <ul className="space-y-2 text-sm text-slate-300">
              {(data.risk?.reasons || ["No elevated risk reasons reported."]).map((reason) => <li key={reason}>- {reason}</li>)}
            </ul>
          </div>
        </section>

        <section className="panel p-5">
          <div className="metric-label mb-3">Behavioral Analysis</div>
          <div className="h-56">
            <ResponsiveContainer>
              <BarChart data={bars}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} />
                <Tooltip contentStyle={{ background: "#0c1728", border: "1px solid #1e3554", color: "#e5eef9" }} />
                <Bar dataKey="baseline" fill="#334155" radius={[4, 4, 0, 0]} />
                <Bar dataKey="current" fill="#38bdf8" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </section>

        <section className="panel p-5">
          <div className="metric-label mb-3">Application Access Matrix</div>
          <AccessMatrix matrix={data.matrix || []} onSelect={onDecisionSelect} />
        </section>
      </div>
    </div>
  );
}

function Info({ label, value }) {
  return (
    <div className="panel-soft p-3">
      <div className="metric-label">{label}</div>
      <div className="mt-1 font-semibold text-white">{value}</div>
    </div>
  );
}
