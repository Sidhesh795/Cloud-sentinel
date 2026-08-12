import { AlertTriangle, Database, Shield, Users } from "lucide-react";
import { Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import AccessMatrix from "../components/security/AccessMatrix.jsx";
import RiskGauge from "../components/security/RiskGauge.jsx";
import PostureTags from "../components/security/PostureTags.jsx";
import SimulationPanel from "../components/security/SimulationPanel.jsx";
import { Badge } from "../components/common/Badge.jsx";
import { compactDate, decisionTone, riskTone, severityTone, titleCase } from "../utils/format.js";

export default function Dashboard({ data, onSelectUser, onDecisionSelect, simulation }) {
  const selected = data.selected;
  const matrix = data.matrix || [];
  const events = data.events || [];
  const blocked = matrix.filter((item) => ["DENY", "ISOLATE", "READ_ONLY"].includes(item.decision)).length;
  const highRiskUsers = data.userSummaries.filter((item) => ["HIGH", "CRITICAL"].includes(item.risk?.risk_level)).length;
  const trend = (data.riskHistory || []).map((item, index) => ({
    label: compactDate(item.timestamp) || `T${index + 1}`,
    risk: item.risk_score
  }));

  return (
    <div className="space-y-5">
      <section className="grid grid-cols-[1.15fr_1.4fr] gap-5">
        <div className="panel p-5">
          <div className="mb-4 flex items-start justify-between">
            <div>
              <div className="metric-label">Current Security Context</div>
              <h2 className="mt-1 text-xl font-bold text-white">{selected?.display_name || "No user selected"}</h2>
              <p className="text-sm text-slate-400">{selected?.username} / {selected?.role}</p>
            </div>
            <RiskGauge score={data.risk?.risk_score || 0} level={data.risk?.risk_level || "LOW"} />
          </div>
          <PostureTags tags={data.posture?.security_tags || []} />
        </div>

        <div className="panel p-5">
          <div className="mb-4 flex items-center justify-between">
            <div>
              <div className="metric-label">Application Access</div>
              <h2 className="mt-1 text-xl font-bold text-white">Resource-Level Enforcement</h2>
            </div>
            <Badge className="border-sky-400/30 bg-sky-400/10 text-sky-300">Backend Decisions</Badge>
          </div>
          <AccessMatrix matrix={matrix} onSelect={onDecisionSelect} />
        </div>
      </section>

      <SimulationPanel simulation={simulation} data={data} />

      <section className="grid grid-cols-4 gap-4">
        <Metric icon={Users} label="Total Users" value={data.users.length} />
        <Metric icon={AlertTriangle} label="High Risk Users" value={highRiskUsers} tone="text-orange-300" />
        <Metric icon={Database} label="Blocked Resources" value={blocked} tone="text-red-300" />
        <Metric icon={Shield} label="Active Incidents" value={events.filter((e) => ["HIGH", "CRITICAL"].includes(e.severity)).length} tone="text-sky-300" />
      </section>

      <section className="grid grid-cols-[1fr_1fr_1fr] gap-5">
        <div className="panel p-5">
          <div className="metric-label mb-3">User Risk Monitor</div>
          <div className="space-y-2">
            {data.userSummaries.map((item) => (
              <button
                key={item.user.id}
                onClick={() => onSelectUser(item.user.id)}
                className="focus-ring flex w-full items-center justify-between rounded-md border border-sentinel-border bg-white/[0.02] px-3 py-3 text-left hover:bg-sky-400/5"
              >
                <div>
                  <div className="font-semibold text-white">{item.user.username}</div>
                  <div className="text-xs text-slate-400">{item.user.role}</div>
                </div>
                <Badge className={riskTone(item.risk?.risk_level)}>{item.risk?.risk_score ?? "--"} {item.risk?.risk_level}</Badge>
              </button>
            ))}
          </div>
        </div>

        <div className="panel p-5">
          <div className="metric-label mb-3">Risk Trend</div>
          <div className="h-64">
            <ResponsiveContainer>
              <LineChart data={trend}>
                <XAxis dataKey="label" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" domain={[0, 100]} fontSize={11} />
                <Tooltip contentStyle={{ background: "#0c1728", border: "1px solid #1e3554", color: "#e5eef9" }} />
                <Line type="monotone" dataKey="risk" stroke="#38bdf8" strokeWidth={3} dot={{ fill: "#38bdf8" }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="panel p-5">
          <div className="metric-label mb-3">Live Security Events</div>
          <div className="space-y-3">
            {events.slice(0, 7).map((event) => (
              <div key={event.id} className="border-l border-sentinel-border pl-3">
                <div className="flex items-center justify-between text-xs">
                  <span className={severityTone(event.severity)}>{event.severity}</span>
                  <span className="text-slate-500">{compactDate(event.timestamp)}</span>
                </div>
                <div className="mt-1 text-sm font-semibold text-slate-100">{titleCase(event.event_type)}</div>
                <div className="text-xs text-slate-400">{event.description}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="panel p-5">
        <div className="metric-label mb-3">Multi-Cloud Enforcement Layer</div>
        <div className="grid grid-cols-3 gap-4">
          {["AWS", "AZURE", "GCP"].map((cloud) => (
            <div key={cloud} className="panel-soft p-4">
              <div className="mb-3 text-sm font-black tracking-[0.14em] text-sky-200">{cloud}</div>
              <div className="space-y-2">
                {matrix.filter((item) => item.cloud === cloud).map((item) => (
                  <div key={item.application_id} className="flex items-center justify-between text-sm">
                    <span>{item.application}</span>
                    <Badge className={decisionTone(item.decision)}>{titleCase(item.decision)}</Badge>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

function Metric({ icon: Icon, label, value, tone = "text-white" }) {
  return (
    <div className="panel p-4">
      <div className="flex items-center justify-between">
        <div>
          <div className="metric-label">{label}</div>
          <div className={`mt-2 text-3xl font-black ${tone}`}>{value}</div>
        </div>
        <Icon className="h-7 w-7 text-sky-300/70" />
      </div>
    </div>
  );
}
