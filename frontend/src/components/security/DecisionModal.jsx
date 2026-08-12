import { X } from "lucide-react";
import { Badge } from "../common/Badge.jsx";
import { decisionTone, titleCase } from "../../utils/format.js";

export default function DecisionModal({ decision, onClose }) {
  if (!decision) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="panel w-full max-w-3xl p-5">
        <div className="flex items-start justify-between border-b border-sentinel-border pb-4">
          <div>
            <div className="metric-label">Zero Trust Decision</div>
            <h2 className="mt-1 text-2xl font-bold text-white">{decision.application.name}</h2>
          </div>
          <button aria-label="Close decision detail" className="focus-ring rounded-md p-2 text-slate-400 hover:bg-white/5 hover:text-white" onClick={onClose}>
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="mt-5 grid gap-4 md:grid-cols-2">
          <Info label="Cloud" value={decision.application.cloud_provider} />
          <Info label="Resource Sensitivity" value={`${decision.resource_sensitivity} / 100 (${decision.resource_level})`} />
          <Info label="User Risk" value={`${decision.risk_score} / 100 (${decision.risk_level})`} />
          <Info label="Policy Rule" value={decision.policy_rule} />
        </div>
        <div className="mt-5">
          <div className="metric-label mb-2">Security Factors</div>
          <div className="flex flex-wrap gap-2">
            {decision.factors?.map((factor) => (
              <Badge key={factor} className="border-slate-500/30 bg-slate-500/10 text-slate-200">{titleCase(factor)}</Badge>
            ))}
          </div>
        </div>
        <div className="mt-5 rounded-lg border border-sentinel-border bg-black/18 p-4">
          <div className="metric-label">Final Decision</div>
          <Badge className={`mt-2 ${decisionTone(decision.decision)}`}>{titleCase(decision.decision)}</Badge>
          <p className="mt-4 text-sm leading-6 text-slate-300">{decision.reason}</p>
        </div>
      </div>
    </div>
  );
}

function Info({ label, value }) {
  return (
    <div className="panel-soft p-3">
      <div className="metric-label">{label}</div>
      <div className="mt-1 text-sm font-semibold text-slate-100">{value}</div>
    </div>
  );
}
