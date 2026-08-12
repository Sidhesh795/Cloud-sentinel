import { riskTone } from "../../utils/format.js";

export default function RiskGauge({ score = 0, level = "LOW", size = "large" }) {
  const radius = size === "small" ? 34 : 54;
  const stroke = size === "small" ? 7 : 10;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (Math.max(0, Math.min(score, 100)) / 100) * circumference;
  return (
    <div className="flex items-center gap-5">
      <svg width={radius * 2 + 18} height={radius * 2 + 18} className="-rotate-90">
        <circle cx={radius + 9} cy={radius + 9} r={radius} stroke="#1e3554" strokeWidth={stroke} fill="none" />
        <circle
          cx={radius + 9}
          cy={radius + 9}
          r={radius}
          stroke={score >= 80 ? "#f87171" : score >= 60 ? "#fb923c" : score >= 30 ? "#fbbf24" : "#34d399"}
          strokeWidth={stroke}
          strokeLinecap="round"
          fill="none"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          className="transition-all duration-700"
        />
      </svg>
      <div>
        <div className={size === "small" ? "text-3xl font-black" : "text-5xl font-black"}>{score}</div>
        <div className={`mt-2 inline-flex rounded-md border px-2 py-1 text-xs font-bold ${riskTone(level)}`}>{level}</div>
      </div>
    </div>
  );
}
