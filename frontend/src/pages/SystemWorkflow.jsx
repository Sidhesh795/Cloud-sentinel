import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, ArrowDown, Cloud, Cpu, Database, FileClock, Lock, RotateCcw, Shield, ShieldCheck, Zap, X } from "lucide-react";
import { Badge } from "../components/common/Badge.jsx";
import WorkflowNode from "../components/security/WorkflowNode.jsx";
import { decisionTone, riskTone, severityTone, titleCase } from "../utils/format.js";

const STAGES = [
  "USER",
  "IDENTITY & MFA",
  "ZERO TRUST GATEWAY",
  "DEVICE POSTURE",
  "BEHAVIOR ANALYSIS",
  "SECURITY TAGS",
  "AI RISK ENGINE",
  "RISK SCORE",
  "ADAPTIVE POLICY",
  "MULTI-CLOUD RESOURCES",
  "ENFORCEMENT",
  "AUDIT"
];

const ATTACK_STAGE_MAP = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

export default function SystemWorkflow({ data, simulation }) {
  const [liveMode, setLiveMode] = useState(true);
  const [simulationMode, setSimulationMode] = useState(true);
  const [viewMode, setViewMode] = useState("NORMAL");
  const [selectedNode, setSelectedNode] = useState(null);

  useEffect(() => {
    if (simulation.status?.state === "COMPROMISED") {
      setViewMode("COMPROMISED");
    }
  }, [simulation.status?.state]);

  const selected = data.selected || {};
  const posture = data.posture || {};
  const risk = data.risk || {};
  const matrix = data.matrix || [];
  const events = data.events || [];
  const telemetry = data.telemetry || [];
  const latestTelemetry = telemetry[0];
  const baselineTelemetry = telemetry[telemetry.length - 1] || latestTelemetry;
  const isCompromised = viewMode === "COMPROMISED" || simulation.status?.state === "COMPROMISED";
  const stageIndex = simulation.running ? Math.min(ATTACK_STAGE_MAP[Math.min(simulation.progress.length, ATTACK_STAGE_MAP.length - 1)], STAGES.length - 1) : isCompromised ? STAGES.length - 1 : 0;

  const riskComponents = risk.components || {};
  const currentTags = liveMode ? (posture.security_tags || []) : [];
  const postureTags = currentTags.map((tag) => tag.tag);
  const postureSummary = liveMode ? (posture.posture_status || "STATIC") : "STATIC";
  const postureRisk = liveMode ? (posture.posture_risk ?? 0) : 0;
  const score = liveMode ? (risk.risk_score ?? 0) : 7;
  const level = liveMode ? (risk.risk_level || "LOW") : "LOW";
  const lowRiskCount = matrix.filter((item) => item.decision === "ALLOW").length;
  const mediumRiskCount = matrix.filter((item) => item.decision === "MFA_REQUIRED").length;
  const restrictedCount = matrix.filter((item) => ["READ_ONLY", "DENY", "ISOLATE"].includes(item.decision)).length;

  const nodeData = useMemo(() => {
    const cloudGroups = matrix.reduce((accumulator, item) => {
      const key = item.cloud || "UNKNOWN";
      if (!accumulator[key]) accumulator[key] = [];
      accumulator[key].push(item);
      return accumulator;
    }, {});

    return [
      {
        id: "user",
        step: "01",
        title: "USER",
        subtitle: selected.username || "developer01",
        explanation: "User requests access to a cloud application.",
        inputLabel: "Input",
        inputValue: "Identity",
        outputLabel: "Output",
        outputValue: "Access Request",
        details: [selected.display_name || "Developer", selected.role || "user"],
        tone: "healthy"
      },
      {
        id: "identity",
        step: "02",
        title: "IDENTITY & MFA",
        subtitle: "Authentication layer",
        explanation: "Establishes the authenticated identity before any access evaluation begins.",
        inputLabel: "Input",
        inputValue: "Credentials",
        outputLabel: "Output",
        outputValue: "Authenticated Identity",
        details: ["JWT authenticated", "MFA verified"],
        tone: liveMode && level !== "LOW" ? "warning" : "healthy"
      },
      {
        id: "gateway",
        step: "03",
        title: "ZERO TRUST GATEWAY",
        subtitle: "Continuous evaluation",
        explanation: "Every access request is evaluated continuously with contextual security signals.",
        inputLabel: "Input",
        inputValue: "User + Request",
        outputLabel: "Output",
        outputValue: "Evaluation Context",
        details: ["Identity", "Application", "Action"],
        tone: liveMode && isCompromised ? "warning" : "neutral"
      },
      {
        id: "posture",
        step: "04",
        title: "DEVICE POSTURE",
        subtitle: postureSummary,
        explanation: "Evaluates whether the endpoint and its context are trustworthy.",
        inputLabel: "Signals",
        inputValue: liveMode
          ? `${posture.deviceCount || (posture.devices?.length || 0)} device • ${selected.device_id || posture.devices?.[0]?.device_id || "registered endpoint"}`
          : "Trusted Device / OS / AV / Location",
        outputLabel: "Output",
        outputValue: liveMode ? `Posture Risk ${postureRisk}/100` : "Posture State",
        details: liveMode
          ? [
              ...(postureTags.includes("TRUSTED_DEVICE") ? ["Trusted Device"] : []),
              ...(postureTags.includes("OS_COMPLIANT") ? ["OS Compliant"] : []),
              ...(postureTags.includes("AV_ACTIVE") ? ["AV Active"] : []),
              ...(postureTags.includes("NORMAL_LOCATION") ? ["Normal Location"] : []),
              ...(postureTags.includes("NEW_LOCATION") ? ["New Location"] : [])
            ]
          : ["Trusted Device", "OS Compliance", "AV Status", "Location"],
        tone: liveMode && isCompromised ? "restricted" : "healthy"
      },
      {
        id: "behavior",
        step: "05",
        title: "BEHAVIOR ANALYSIS",
        subtitle: "Telemetry baseline comparison",
        explanation: "Compares current activity against behavioral baselines.",
        inputLabel: "Signals",
        inputValue: liveMode
          ? `${latestTelemetry?.requests_per_minute ?? 0} req/min • ${latestTelemetry?.data_download_mb ?? 0} MB • ${latestTelemetry?.failed_logins ?? 0} failed logins`
          : "Requests / Data Transfer / Failed Logins / Usage",
        outputLabel: "Output",
        outputValue: liveMode ? `Behavioral Signal ${riskComponents.behavior || 0}/100` : "Behavioral Signal",
        details: liveMode
          ? [
              `Requests ${latestTelemetry?.requests_per_minute ?? "--"}`,
              `Data ${latestTelemetry?.data_download_mb ?? "--"} MB`,
              `Failed logins ${latestTelemetry?.failed_logins ?? "--"}`,
              `Applications ${latestTelemetry?.unique_applications ?? "--"}`
            ]
          : ["Requests", "Data Transfer", "Failed Logins", "Application Usage"],
        tone: liveMode && isCompromised ? "warning" : "neutral"
      },
      {
        id: "tags",
        step: "06",
        title: "SECURITY TAGS",
        subtitle: "Derived security context",
        explanation: "Machine-readable tags carry the posture and anomaly context forward.",
        inputLabel: "Signals",
        inputValue: liveMode ? (postureTags.length ? postureTags.slice(0, 4).join(" • ") : "No active tags") : "Security context tags",
        outputLabel: "Output",
        outputValue: "Security Context",
        details: liveMode ? postureTags.slice(0, 5) : ["TRUSTED_DEVICE", "NEW_LOCATION", "AUTH_ANOMALY", "DATA_EXFILTRATION", "THREAT_DETECTED"],
        tone: liveMode && isCompromised ? "warning" : "healthy"
      },
      {
        id: "risk-engine",
        step: "07",
        title: "AI RISK ENGINE",
        subtitle: "Transparent scoring",
        explanation: "Combines security signals into a transparent risk assessment.",
        inputLabel: "Inputs",
        inputValue: liveMode
          ? `Identity ${riskComponents.identity ?? 0} • Posture ${riskComponents.posture ?? 0} • Behavior ${riskComponents.behavior ?? 0}`
          : "Identity / Posture / Behavior / Context / Resource Sensitivity",
        outputLabel: "Output",
        outputValue: liveMode ? `Risk Score ${score}/100` : "Risk Score",
        details: ["Isolation Forest", "Transparent scoring", "Behavioral anomaly detection"],
        tone: liveMode && level === "LOW" ? "healthy" : liveMode && level === "MEDIUM" ? "warning" : "restricted"
      },
      {
        id: "risk-score",
        step: "08",
        title: "RISK SCORE",
        subtitle: `${score} / 100`,
        explanation: "A compact score maps context into LOW, MEDIUM, HIGH, or CRITICAL risk.",
        inputLabel: "Scale",
        inputValue: "0 ─────────────── 100",
        outputLabel: "Current Level",
        outputValue: level,
        details: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        tone: level === "LOW" ? "healthy" : level === "MEDIUM" ? "warning" : "restricted"
      },
      {
        id: "policy",
        step: "09",
        title: "ADAPTIVE POLICY",
        subtitle: "Context + sensitivity",
        explanation: "Determines the appropriate access level for the current context.",
        inputLabel: "Inputs",
        inputValue: liveMode
          ? `${score} risk + resource sensitivity + security context + user role`
          : "Risk + Resource Sensitivity + Security Context + User Role",
        outputLabel: "Output",
        outputValue: liveMode ? "Policy Decision" : "Policy Decision",
        details: ["Risk", "Resource Sensitivity", "Security Context", "User Role"],
        tone: liveMode && isCompromised ? "warning" : "neutral"
      },
      {
        id: "resources",
        step: "10",
        title: "MULTI-CLOUD RESOURCES",
        subtitle: "Resource-specific decisions",
        explanation: "Different cloud applications receive different access decisions based on sensitivity.",
        inputLabel: "Clouds",
        inputValue: "AWS / Azure / GCP",
        outputLabel: "Output",
        outputValue: `${matrix.length} active decisions`,
        details: [
          `${cloudGroups.AWS?.length || 0} AWS`,
          `${cloudGroups.AZURE?.length || 0} Azure`,
          `${cloudGroups.GCP?.length || 0} GCP`
        ],
        tone: "neutral"
      },
      {
        id: "enforcement",
        step: "11",
        title: "ENFORCEMENT",
        subtitle: "Blast-radius reduction",
        explanation: "The system applies the least disruptive control required for each resource.",
        inputLabel: "Possible actions",
        inputValue: "ALLOW / MFA / READ ONLY / DENY / ISOLATE",
        outputLabel: "Output",
        outputValue: liveMode
          ? `${lowRiskCount} allow • ${mediumRiskCount} step-up • ${restrictedCount} restricted`
          : "Access decision",
        details: ["ALLOW", "MFA REQUIRED", "READ ONLY", "DENY", "ISOLATE"],
        tone: isCompromised ? "restricted" : "healthy"
      },
      {
        id: "audit",
        step: "12",
        title: "AUDIT & DASHBOARD",
        subtitle: "Observable control plane",
        explanation: "Every decision becomes observable and auditable.",
        inputLabel: "Signals",
        inputValue: "Risk history / Access decisions / Security events",
        outputLabel: "Output",
        outputValue: `${events.length} security events`,
        details: ["Risk History", "Access Decisions", "Security Tags", "Audit Logs"],
        tone: "neutral"
      }
    ];
  }, [baselineTelemetry, events.length, isCompromised, latestTelemetry, liveMode, matrix, posture, postureRisk, postureTags, risk, score, selected]);

  const selectedNodeData = nodeData.find((item) => item.id === selectedNode) || nodeData[6];
  const compromisedMatrix = matrix.map((item) => ({
    ...item,
    decision: viewMode === "COMPROMISED" && ["Email", "HR Portal"].includes(item.application)
      ? "MFA_REQUIRED"
      : viewMode === "COMPROMISED" && ["Cloud Storage"].includes(item.application)
        ? "READ_ONLY"
        : viewMode === "COMPROMISED" && ["Customer Database", "Admin Console"].includes(item.application)
          ? "DENY"
          : item.decision
  }));

  return (
    <div className="space-y-5">
      <section className="panel p-5">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div className="min-w-0">
            <div className="metric-label">System Workflow</div>
            <h2 className="mt-1 text-2xl font-black tracking-[0.12em] text-white md:text-3xl">SYSTEM WORKFLOW</h2>
            <p className="mt-3 max-w-4xl text-sm leading-6 text-slate-400 md:text-base">
              How CloudSentinel continuously evaluates identity, context, behavior and resource sensitivity before granting access.
            </p>
            <div className="mt-4 inline-flex items-center gap-3 rounded-full border border-emerald-400/20 bg-emerald-500/8 px-4 py-2 text-xs font-black uppercase tracking-[0.18em] text-emerald-200">
              <span className="h-2 w-2 rounded-full bg-emerald-400 shadow-[0_0_16px_rgba(52,211,153,0.75)] workflow-pulse" />
              Zero Trust Pipeline Active
            </div>
          </div>

          <div className="grid gap-3 sm:grid-cols-2 xl:min-w-[420px] xl:grid-cols-2">
            <Toggle label="Live System Data" value={liveMode} onClick={() => setLiveMode((current) => !current)} icon={ShieldCheck} />
            <Toggle label="Simulation Mode" value={simulationMode} onClick={() => setSimulationMode((current) => !current)} icon={Zap} />
            <Toggle label="Normal State" value={viewMode === "NORMAL"} onClick={() => setViewMode("NORMAL")} icon={Shield} small />
            <Toggle label="Compromised State" value={viewMode === "COMPROMISED"} onClick={() => setViewMode("COMPROMISED")} icon={AlertTriangle} small />
          </div>
        </div>

        <div className="mt-5 flex flex-wrap gap-2">
          {STAGES.map((stage, index) => (
            <button
              key={stage}
              type="button"
              onClick={() => setSelectedNode(nodeData[index].id)}
              className={`focus-ring rounded-full border px-3 py-1.5 text-[11px] font-bold uppercase tracking-[0.14em] transition ${
                index <= stageIndex
                  ? "border-sky-400/25 bg-sky-400/10 text-sky-100"
                  : "border-sentinel-border bg-white/[0.02] text-slate-400 hover:bg-white/[0.04]"
              }`}
            >
              {String(index + 1).padStart(2, "0")} {stage}
            </button>
          ))}
        </div>
      </section>

      <section className="panel p-5">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <div className="metric-label">Simulation Control</div>
            <h3 className="mt-1 text-xl font-black tracking-[0.12em] text-white">Live compromise walkthrough</h3>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
              Trigger the existing backend simulation to show how risk escalates, policies re-evaluate, and high-sensitivity resources become restricted.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => simulation.runAttack(data)}
              disabled={!data.selected || simulation.running || simulation.status?.state === "COMPROMISED"}
              className="focus-ring inline-flex items-center gap-2 rounded-md bg-red-400 px-4 py-2 text-sm font-bold text-slate-950 transition hover:bg-red-300 disabled:cursor-not-allowed disabled:opacity-45"
            >
              <Zap className="h-4 w-4" />
              Simulate Account Compromise
            </button>
            <button
              type="button"
              onClick={simulation.reset}
              disabled={!data.selected || simulation.running}
              className="focus-ring inline-flex items-center gap-2 rounded-md border border-sentinel-border px-4 py-2 text-sm font-bold text-slate-200 transition hover:bg-white/5 disabled:opacity-45"
            >
              <RotateCcw className="h-4 w-4" />
              Reset Demo
            </button>
          </div>
        </div>

        {simulationMode && simulation.running && (
          <div className="mt-5 grid gap-3 lg:grid-cols-[1fr_0.8fr]">
            <div className="rounded-2xl border border-sentinel-border bg-black/16 p-4">
              <div className="metric-label mb-3">Pipeline Progress</div>
              <div className="flex flex-wrap gap-2">
                {simulation.progress.map((step) => (
                  <Badge key={step} className="border-sky-400/20 bg-sky-400/10 text-sky-100">
                    {step}
                  </Badge>
                ))}
              </div>
            </div>
            <div className="rounded-2xl border border-sentinel-border bg-black/16 p-4">
              <div className="metric-label">Simulation State</div>
              <div className="mt-3 text-sm text-slate-300">
                {simulation.phaseLabel} · {simulation.status?.state || "NORMAL"}
              </div>
            </div>
          </div>
        )}
      </section>

      <section className="grid gap-5 xl:grid-cols-[1.15fr_0.85fr]">
        <div className="space-y-4">
          {nodeData.map((node, index) => (
            <div key={node.id} className="space-y-4">
              <WorkflowNode
                {...node}
                active={index <= stageIndex || node.id === selectedNode}
                onClick={() => setSelectedNode(node.id)}
                tone={node.tone}
              />
              {index < nodeData.length - 1 && (
                <div className="flex justify-center py-1 text-sky-300/70">
                  <div className="workflow-connector flex flex-col items-center gap-1">
                    <span className={`h-2 w-2 rounded-full ${simulationMode ? "bg-sky-400" : "bg-slate-500"} workflow-flow-dot`} />
                    <ArrowDown className="h-4 w-4" />
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>

        <div className="space-y-5">
          <section className="panel p-5">
            <div className="metric-label">Selected Node</div>
            <h3 className="mt-2 text-xl font-black tracking-[0.12em] text-white">{selectedNodeData.title}</h3>
            <p className="mt-3 text-sm leading-6 text-slate-300">{selectedNodeData.explanation}</p>
            <div className="mt-4 grid gap-3 sm:grid-cols-2">
              <Info label={selectedNodeData.inputLabel} value={selectedNodeData.inputValue} />
              <Info label={selectedNodeData.outputLabel} value={selectedNodeData.outputValue} accent />
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              {selectedNodeData.details.map((detail) => (
                <Badge key={detail} className="border-slate-500/30 bg-slate-500/10 text-slate-200">
                  {detail}
                </Badge>
              ))}
            </div>
          </section>

          <section className="panel p-5">
            <div className="metric-label">Live Risk Context</div>
            <div className="mt-4 flex items-center justify-between gap-4">
              <div>
                <div className="text-sm text-slate-400">Selected user</div>
                <div className="mt-1 text-lg font-bold text-white">{selected.display_name || selected.username || "developer01"}</div>
                <div className="text-sm text-slate-400">{selected.role || "Developer"}</div>
              </div>
              <div className="rounded-2xl border border-sentinel-border bg-black/18 p-4 text-right">
                <div className="text-xs uppercase tracking-[0.14em] text-slate-500">Risk</div>
                <div className={`mt-2 text-4xl font-black ${score < 30 ? "text-emerald-300" : score < 60 ? "text-amber-300" : score < 80 ? "text-orange-300" : "text-red-300"}`}>
                  {score}
                </div>
                <Badge className={`mt-2 ${riskTone(level)}`}>{level}</Badge>
              </div>
            </div>
            <div className="mt-4 grid grid-cols-3 gap-3 text-sm">
              <Stat label="Posture" value={postureSummary || "STATIC"} />
              <Stat label="Tags" value={postureTags.length || 0} />
              <Stat label="Events" value={events.length} />
            </div>
          </section>

          <section className="panel p-5">
            <div className="metric-label">Resource-Level Enforcement</div>
            <div className="mt-4 grid gap-4 md:grid-cols-3">
              {[
                { cloud: "AWS", color: "text-red-300", items: compromisedMatrix.filter((item) => item.cloud === "AWS") },
                { cloud: "AZURE", color: "text-amber-300", items: compromisedMatrix.filter((item) => item.cloud === "AZURE") },
                { cloud: "GCP", color: "text-orange-300", items: compromisedMatrix.filter((item) => item.cloud === "GCP") }
              ].map((group) => (
                <div key={group.cloud} className="panel-soft p-4">
                  <div className={`mb-3 text-sm font-black tracking-[0.14em] ${group.color}`}>{group.cloud}</div>
                  <div className="space-y-2">
                    {group.items.map((item) => (
                      <div key={item.application_id} className="flex items-center justify-between gap-3 rounded-md border border-sentinel-border/80 bg-white/[0.02] px-3 py-2 text-sm">
                        <div>
                          <div className="font-semibold text-white">{item.application}</div>
                          <div className="text-xs text-slate-500">Sensitivity {item.sensitivity}/100</div>
                        </div>
                        <Badge className={decisionTone(item.decision)}>{titleCase(item.decision)}</Badge>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </section>

          <section className="panel p-5">
            <div className="metric-label">Blast Radius</div>
            <div className="mt-4 grid gap-4 lg:grid-cols-2">
              <div className="panel-soft p-4">
                <div className="mb-3 text-sm font-black tracking-[0.14em] text-slate-200">Traditional Response</div>
                <div className="space-y-3 text-sm text-slate-300">
                  <div>Compromised User</div>
                  <ArrowDown className="h-4 w-4 text-slate-500" />
                  <div className="rounded-lg border border-red-400/25 bg-red-500/10 p-3 font-bold text-red-200">BLOCK EVERYTHING</div>
                </div>
              </div>
              <div className="panel-soft p-4">
                <div className="mb-3 text-sm font-black tracking-[0.14em] text-sky-200">CloudSentinel</div>
                <div className="space-y-3 text-sm text-slate-300">
                  <div>Compromised User</div>
                  <ArrowDown className="h-4 w-4 text-slate-500" />
                  <div>Evaluate Each Resource</div>
                  <div className="rounded-lg border border-sentinel-border bg-black/15 p-3">
                    <div className="grid gap-2 sm:grid-cols-2">
                      <Badge className="border-emerald-400/25 bg-emerald-500/10 text-emerald-200">Low Risk → ALLOW</Badge>
                      <Badge className="border-amber-400/25 bg-amber-500/10 text-amber-200">Medium → MFA</Badge>
                      <Badge className="border-orange-400/25 bg-orange-500/10 text-orange-200">High → READ ONLY</Badge>
                      <Badge className="border-red-400/25 bg-red-500/10 text-red-200">Critical → DENY</Badge>
                    </div>
                  </div>
                  <div className="text-center text-xs font-black uppercase tracking-[0.18em] text-red-300">Reduced Blast Radius</div>
                </div>
              </div>
            </div>
          </section>

          <section className="panel p-5">
            <div className="metric-label">Technology Stack</div>
            <div className="mt-4 grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
              <StackBlock title="Frontend" items={["React", "Vite", "Tailwind"]} icon={Cpu} />
              <StackBlock title="Backend" items={["FastAPI", "SQLAlchemy", "SQLite"]} icon={Database} />
              <StackBlock title="Security Intelligence" items={["Isolation Forest", "Risk Engine", "Security Posture Engine"]} icon={Shield} />
              <StackBlock title="Access" items={["Zero Trust Gateway", "Adaptive Policy Engine"]} icon={Lock} />
              <StackBlock title="Cloud" items={["AWS", "Azure", "GCP"]} icon={Cloud} />
              <StackBlock title="Audit" items={["Risk History", "Access Decisions", "Security Events"]} icon={FileClock} />
            </div>
          </section>
        </div>
      </section>

      {simulationMode && simulation.running && (
        <section className="panel p-5">
          <div className="metric-label">Simulation Sequence</div>
          <div className="mt-4 grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
            {simulation.progress.map((step) => (
              <div key={step} className="rounded-md border border-sentinel-border/80 bg-white/[0.02] px-3 py-2 text-sm text-slate-200">
                {step}
              </div>
            ))}
          </div>
        </section>
      )}

      <WorkflowDetailModal
        node={selectedNodeData}
        onClose={() => setSelectedNode(null)}
        open={Boolean(selectedNode)}
        liveMode={liveMode}
        selected={selected}
        posture={posture}
        risk={risk}
        matrix={matrix}
        events={events}
        telemetry={telemetry}
        viewMode={viewMode}
      />
    </div>
  );
}

function Toggle({ label, value, onClick, icon: Icon, small = false }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`focus-ring flex items-center justify-between gap-3 rounded-xl border px-3 py-3 text-left transition ${
        value ? "border-sky-400/30 bg-sky-400/10 text-sky-100" : "border-sentinel-border bg-white/[0.02] text-slate-300 hover:bg-white/[0.04]"
      } ${small ? "text-xs" : "text-sm"}`}
    >
      <span className="flex min-w-0 items-center gap-2">
        <Icon className="h-4 w-4 shrink-0" />
        <span className="truncate font-semibold uppercase tracking-[0.12em]">{label}</span>
      </span>
      <span className={`h-2.5 w-2.5 rounded-full ${value ? "bg-emerald-400 shadow-[0_0_14px_rgba(52,211,153,0.7)]" : "bg-slate-500"}`} />
    </button>
  );
}

function Info({ label, value, accent = false }) {
  return (
    <div className={`rounded-xl border border-sentinel-border/80 bg-black/16 p-3 ${accent ? "ring-1 ring-sky-400/10" : ""}`}>
      <div className="text-[10px] font-bold uppercase tracking-[0.16em] text-slate-500">{label}</div>
      <div className={`mt-1 text-sm font-semibold leading-6 ${accent ? "text-sky-100" : "text-slate-100"}`}>{value}</div>
    </div>
  );
}

function Stat({ label, value }) {
  return (
    <div className="rounded-xl border border-sentinel-border/80 bg-black/16 p-3">
      <div className="text-[10px] font-bold uppercase tracking-[0.16em] text-slate-500">{label}</div>
      <div className="mt-1 text-lg font-black text-white">{value}</div>
    </div>
  );
}

function StackBlock({ title, items, icon: Icon }) {
  return (
    <div className="panel-soft p-4">
      <div className="flex items-center gap-2 text-sm font-black tracking-[0.14em] text-sky-200">
        <Icon className="h-4 w-4" />
        {title}
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        {items.map((item) => (
          <Badge key={item} className="border-sentinel-border bg-white/[0.02] text-slate-200">
            {item}
          </Badge>
        ))}
      </div>
    </div>
  );
}

function WorkflowDetailModal({ node, open, onClose, liveMode, selected, posture, risk, matrix, events, telemetry, viewMode }) {
  if (!open || !node) return null;
  const latestTelemetry = telemetry[0];
  const baselineTelemetry = telemetry[telemetry.length - 1] || latestTelemetry;
  const compromisedMatrix = matrix.map((item) => ({
    ...item,
    decision: viewMode === "COMPROMISED" && ["Email", "HR Portal"].includes(item.application)
      ? "MFA_REQUIRED"
      : viewMode === "COMPROMISED" && ["Cloud Storage"].includes(item.application)
        ? "READ_ONLY"
        : viewMode === "COMPROMISED" && ["Customer Database", "Admin Console"].includes(item.application)
          ? "DENY"
          : item.decision
  }));
  const cloudDecisions = compromisedMatrix.slice(0, 5);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
      <div className="panel max-h-[90vh] w-full max-w-4xl overflow-y-auto p-5">
        <div className="flex items-start justify-between gap-4 border-b border-sentinel-border pb-4">
          <div>
            <div className="metric-label">Workflow Node Details</div>
            <h3 className="mt-1 text-2xl font-black tracking-[0.12em] text-white">{node.title}</h3>
            <p className="mt-2 text-sm text-slate-400">{node.explanation}</p>
          </div>
          <button type="button" aria-label="Close workflow detail" onClick={onClose} className="focus-ring rounded-md p-2 text-slate-400 hover:bg-white/5 hover:text-white">
            <X className="h-5 w-5" />
          </button>
        </div>

        <div className="mt-5 grid gap-4 md:grid-cols-2">
          <Info label="Purpose" value={node.title} />
          <Info label="Current User" value={selected.display_name || selected.username || "developer01"} accent />
          <Info label="Input" value={node.inputValue} />
          <Info label="Output" value={node.outputValue} accent />
        </div>

        <div className="mt-5 grid gap-4 md:grid-cols-2">
          <section className="panel-soft p-4">
            <div className="metric-label mb-3">Live Signals</div>
            <div className="space-y-2 text-sm text-slate-300">
              <Line label="Risk" value={`${risk.risk_score ?? 0} / 100 (${risk.risk_level || "LOW"})`} />
              <Line label="Posture" value={`${posture.posture_status || "STATIC"} / ${posture.posture_risk ?? 0}`} />
              <Line label="Tags" value={(posture.security_tags || []).slice(0, 5).map((tag) => tag.tag).join(" • ") || "None"} />
              <Line label="Behavior" value={latestTelemetry ? `${latestTelemetry.requests_per_minute} req/min, ${latestTelemetry.data_download_mb} MB` : "Unavailable"} />
              <Line label="Baseline" value={baselineTelemetry ? `${baselineTelemetry.requests_per_minute} req/min, ${baselineTelemetry.data_download_mb} MB` : "Unavailable"} />
            </div>
          </section>

          <section className="panel-soft p-4">
            <div className="metric-label mb-3">Associated Decisions</div>
            <div className="space-y-2">
              {cloudDecisions.map((item) => (
                <div key={item.application_id} className="flex items-center justify-between gap-3 rounded-md border border-sentinel-border bg-white/[0.02] px-3 py-2 text-sm">
                  <div>
                    <div className="font-semibold text-white">{item.application}</div>
                    <div className="text-xs text-slate-500">{item.cloud} · Sensitivity {item.sensitivity}/100</div>
                  </div>
                  <Badge className={decisionTone(item.decision)}>{titleCase(item.decision)}</Badge>
                </div>
              ))}
            </div>
          </section>
        </div>

        {node.id === "risk-engine" && (
          <section className="mt-5 panel-soft p-4">
            <div className="metric-label mb-3">Technology</div>
            <div className="text-sm leading-6 text-slate-300">
              Combines multiple security signals into a dynamic risk score using isolation-forest-based anomaly detection and transparent scoring.
            </div>
          </section>
        )}

        <section className="mt-5 panel-soft p-4">
          <div className="metric-label mb-3">Observability</div>
          <div className="grid gap-3 md:grid-cols-3">
            <Info label="Risk history" value={`${(events || []).length} tracked events`} />
            <Info label="Access decisions" value={`${matrix.length} resources evaluated`} />
            <Info label="Simulation" value={liveMode ? viewMode : "Static demo"} accent />
          </div>
        </section>
      </div>
    </div>
  );
}

function Line({ label, value }) {
  return (
    <div className="flex items-start justify-between gap-4 rounded-md border border-sentinel-border/70 bg-black/14 px-3 py-2">
      <span className="text-xs uppercase tracking-[0.14em] text-slate-500">{label}</span>
      <span className="text-right text-sm font-semibold text-slate-100">{value}</span>
    </div>
  );
}