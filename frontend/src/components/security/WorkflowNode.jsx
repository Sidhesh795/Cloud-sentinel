import { ArrowDown, ArrowRight } from "lucide-react";
import { Badge } from "../common/Badge.jsx";

const toneClasses = {
  healthy: "border-emerald-400/20 bg-emerald-500/6",
  warning: "border-amber-400/20 bg-amber-500/6",
  restricted: "border-orange-400/20 bg-orange-500/6",
  threat: "border-red-400/20 bg-red-500/6",
  neutral: "border-sky-400/20 bg-sky-500/6"
};

const dotClasses = {
  healthy: "bg-emerald-400",
  warning: "bg-amber-400",
  restricted: "bg-orange-400",
  threat: "bg-red-400",
  neutral: "bg-sky-400"
};

export default function WorkflowNode({
  step,
  title,
  subtitle,
  explanation,
  inputLabel,
  inputValue,
  outputLabel,
  outputValue,
  details = [],
  tone = "neutral",
  active = false,
  onClick,
  compact = false
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={`Open details for ${title}`}
      className={`workflow-node focus-ring group w-full rounded-2xl border p-4 text-left transition duration-200 hover:-translate-y-0.5 hover:border-sky-300/40 hover:bg-white/[0.035] ${toneClasses[tone]} ${active ? "workflow-node-active shadow-[0_0_0_1px_rgba(56,189,248,0.2),0_0_28px_rgba(56,189,248,0.08)]" : "shadow-none"}`}
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <span className={`h-2.5 w-2.5 rounded-full ${dotClasses[tone]} ${active ? "animate-pulse" : ""}`} />
            <div className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-400">Step {step}</div>
          </div>
          <h3 className="mt-2 text-lg font-black tracking-[0.12em] text-white">{title}</h3>
          {subtitle && <div className="mt-1 text-xs uppercase tracking-[0.16em] text-sky-200/80">{subtitle}</div>}
        </div>
        {active && <Badge className="border-sky-400/25 bg-sky-400/10 text-sky-200">ACTIVE</Badge>}
      </div>

      <p className={`mt-3 leading-6 text-slate-300 ${compact ? "text-xs" : "text-sm"}`}>{explanation}</p>

      <div className="mt-4 grid gap-3 md:grid-cols-2">
        <Field label={inputLabel} value={inputValue} compact={compact} />
        <Field label={outputLabel} value={outputValue} compact={compact} emphasize />
      </div>

      {details.length > 0 && (
        <div className="mt-4 flex flex-wrap gap-2">
          {details.map((detail) => (
            <Badge key={detail} className="border-slate-500/30 bg-slate-500/10 text-slate-200">
              {detail}
            </Badge>
          ))}
        </div>
      )}

      <div className="mt-4 flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-slate-500 group-hover:text-slate-300">
        <span className="h-px flex-1 bg-gradient-to-r from-transparent via-slate-600 to-transparent" />
        <span className="hidden md:inline">Inspect node</span>
        <ArrowRight className="hidden h-3 w-3 md:inline" />
        <ArrowDown className="h-3 w-3 md:hidden" />
      </div>
    </button>
  );
}

function Field({ label, value, compact, emphasize = false }) {
  return (
    <div className={`rounded-xl border border-sentinel-border/80 bg-black/16 p-3 ${emphasize ? "ring-1 ring-sky-400/10" : ""}`}>
      <div className="text-[10px] font-bold uppercase tracking-[0.16em] text-slate-500">{label}</div>
      <div className={`mt-1 ${compact ? "text-xs" : "text-sm"} font-semibold leading-6 ${emphasize ? "text-sky-100" : "text-slate-100"}`}>
        {value}
      </div>
    </div>
  );
}