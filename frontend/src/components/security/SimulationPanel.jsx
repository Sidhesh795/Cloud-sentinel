import { AlertTriangle, RotateCcw, ShieldCheck, Zap } from "lucide-react";
import { decisionTone } from "../../utils/format.js";
import { Badge } from "../common/Badge.jsx";

const isAvailable = (decision) => ["ALLOW", "MFA_REQUIRED"].includes(decision);
const isRestricted = (decision) => ["READ_ONLY", "DENY", "ISOLATE"].includes(decision);
const isBlocked = (decision) => ["DENY", "ISOLATE"].includes(decision);

export default function SimulationPanel({ simulation, data }) {
  const status = simulation.status || data?.simulationStatus;
  const isOwnUser = data?.selected?.id === data?.currentUser?.id;
  const isAdmin = data?.selected?.role === "admin";
  const after = data?.matrix || [];
  const before = simulation.beforeSnapshot?.matrix || after;
  const beforeAccessible = before.filter((item) => isAvailable(item.decision)).length;
  const afterAccessible = after.filter((item) => isAvailable(item.decision)).length;
  const restricted = after.filter((item) => isRestricted(item.decision)).length;
  const blocked = after.filter((item) => isBlocked(item.decision)).length;
  const lowRiskAvailable = after.filter((item) => item.sensitivity < 60 && isAvailable(item.decision)).length;
  const beforeRisk = simulation.beforeSnapshot?.risk?.risk_score ?? data?.risk?.risk_score;
  const afterRisk = data?.risk?.risk_score;

  return (
    <section className="panel p-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="metric-label">Live Demo Control</div>
          <div className="mt-2 flex items-center gap-2">
            {status?.state === "COMPROMISED" ? (
              <AlertTriangle className="h-5 w-5 text-red-300" />
            ) : (
              <ShieldCheck className="h-5 w-5 text-emerald-300" />
            )}
            <h3 className="text-lg font-bold text-white">{simulation.phaseLabel}</h3>
          </div>
          <p className="mt-2 max-w-2xl text-sm text-slate-400">
            Controlled account-compromise simulation demonstrating continuous Zero Trust evaluation.
          </p>
          {isAdmin && (
            <div className="mt-3 inline-flex rounded-md border border-sky-400/25 bg-sky-400/10 px-3 py-1.5 text-xs font-bold uppercase tracking-[0.12em] text-sky-200">
              Administrator / Privileged Access
            </div>
          )}
          {!isOwnUser && (
            <p className="mt-3 text-xs text-amber-300">
              Simulation controls are available only for the authenticated user.
            </p>
          )}
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => simulation.runAttack(data)}
            disabled={!isOwnUser || simulation.running || status?.state === "COMPROMISED"}
            className="focus-ring inline-flex items-center gap-2 rounded-md bg-red-400 px-4 py-2 text-sm font-bold text-slate-950 transition hover:bg-red-300 disabled:cursor-not-allowed disabled:opacity-45"
          >
            <Zap className="h-4 w-4" />
            Simulate Account Compromise
          </button>
          <button
            onClick={simulation.reset}
            disabled={!isOwnUser || simulation.running}
            className="focus-ring inline-flex items-center gap-2 rounded-md border border-sentinel-border px-4 py-2 text-sm font-bold text-slate-200 transition hover:bg-white/5 disabled:opacity-45"
          >
            <RotateCcw className="h-4 w-4" />
            Reset Demo
          </button>
        </div>
      </div>

      {(simulation.running || simulation.progress.length > 0) && (
        <div className="mt-5 grid grid-cols-[1fr_0.75fr] gap-4">
          <div className="panel-soft p-4">
            <div className="metric-label mb-3">Simulation Sequence</div>
            <div className="space-y-2">
              {simulation.progress.map((step) => (
                <div key={step} className="flex items-center gap-2 text-sm text-slate-200">
                  <span className="h-2 w-2 rounded-full bg-sky-300" />
                  {step}
                </div>
              ))}
            </div>
          </div>
          <div className="panel-soft p-4">
            <div className="metric-label">Risk Transition</div>
            <div className="mt-3 text-3xl font-black text-white">{beforeRisk ?? "--"} <span className="text-slate-500">to</span> {afterRisk ?? "--"}</div>
            <div className="mt-3 h-2 rounded-full bg-slate-800">
              <div className="h-2 rounded-full bg-red-400 transition-all duration-700" style={{ width: `${Math.min(afterRisk || 0, 100)}%` }} />
            </div>
          </div>
        </div>
      )}

      {status?.state === "COMPROMISED" && !simulation.running && (
        <div className="mt-5 grid grid-cols-[0.9fr_1.1fr] gap-4">
          <div className="panel-soft p-4">
            <div className="metric-label">Threat Contained</div>
            <div className="mt-3 grid grid-cols-2 gap-3 text-sm">
              <Metric label="Risk" value={`${beforeRisk ?? "--"} to ${afterRisk ?? "--"}`} />
              <Metric label="Critical blocked" value={blocked} />
              <Metric label="Restricted resources" value={restricted} />
              <Metric label="Low-risk available" value={lowRiskAvailable} />
            </div>
            <p className="mt-4 text-sm text-slate-300">
              {isAdmin
                ? "High-risk privileged session requires step-up verification while authorized cloud access is retained."
                : "User remains partially operational while high-risk resources are isolated."}
            </p>
          </div>
          <div className="panel-soft p-4">
            <div className="metric-label">Blast Radius</div>
            <div className="mt-4 flex items-center gap-4">
              <Blast label="Before" value={beforeAccessible} total={before.length || 1} />
              <div className="text-slate-500">to</div>
              <Blast label="After" value={afterAccessible} total={after.length || 1} />
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              {after.map((item) => (
                <Badge key={item.application_id} className={decisionTone(item.decision)}>{item.application}</Badge>
              ))}
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

function Metric({ label, value }) {
  return (
    <div className="rounded-md border border-sentinel-border bg-black/15 p-3">
      <div className="text-xs uppercase tracking-[0.12em] text-slate-500">{label}</div>
      <div className="mt-1 text-xl font-black text-white">{value}</div>
    </div>
  );
}

function Blast({ label, value, total }) {
  const pct = Math.round((value / total) * 100);
  return (
    <div className="flex-1">
      <div className="flex justify-between text-xs text-slate-400">
        <span>{label}</span>
        <span>{value} reachable</span>
      </div>
      <div className="mt-2 h-3 rounded-full bg-slate-800">
        <div className="h-3 rounded-full bg-sky-400 transition-all duration-700" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}
