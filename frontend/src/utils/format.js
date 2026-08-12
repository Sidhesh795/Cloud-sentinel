export const riskTone = (level) => {
  const normalized = String(level || "").toUpperCase();
  if (normalized === "CRITICAL") return "text-red-300 bg-red-500/12 border-red-400/30";
  if (normalized === "HIGH") return "text-orange-300 bg-orange-500/12 border-orange-400/30";
  if (normalized === "MEDIUM") return "text-amber-300 bg-amber-500/12 border-amber-400/30";
  return "text-emerald-300 bg-emerald-500/12 border-emerald-400/30";
};

export const decisionTone = (decision) => {
  if (decision === "DENY" || decision === "ISOLATE") return "text-red-300 bg-red-500/12 border-red-400/30";
  if (decision === "READ_ONLY") return "text-orange-300 bg-orange-500/12 border-orange-400/30";
  if (decision === "MFA_REQUIRED") return "text-amber-300 bg-amber-500/12 border-amber-400/30";
  return "text-emerald-300 bg-emerald-500/12 border-emerald-400/30";
};

export const tagTone = (severity) => {
  const value = String(severity || "").toUpperCase();
  if (value === "CRITICAL" || value === "HIGH") return "text-red-300 bg-red-500/12 border-red-400/30";
  if (value === "MEDIUM") return "text-amber-300 bg-amber-500/12 border-amber-400/30";
  return "text-emerald-300 bg-emerald-500/12 border-emerald-400/30";
};

export const severityTone = (severity) => {
  const value = String(severity || "").toUpperCase();
  if (value === "CRITICAL") return "text-red-300";
  if (value === "HIGH") return "text-orange-300";
  if (value === "MEDIUM") return "text-amber-300";
  if (value === "LOW") return "text-emerald-300";
  return "text-sky-300";
};

export const compactDate = (value) => {
  if (!value) return "No timestamp";
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  }).format(new Date(value));
};

export const titleCase = (value) => String(value || "").replaceAll("_", " ");
