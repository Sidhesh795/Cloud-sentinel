import { decisionTone, titleCase } from "../../utils/format.js";
import { Badge } from "../common/Badge.jsx";

export default function AccessMatrix({ matrix = [], onSelect }) {
  if (!matrix.length) return <div className="text-sm text-slate-400">No access decisions available.</div>;
  return (
    <div className="overflow-hidden rounded-lg border border-sentinel-border">
      <table className="w-full text-left text-sm">
        <thead className="bg-white/[0.03] text-xs uppercase tracking-[0.12em] text-slate-400">
          <tr>
            <th className="px-4 py-3">Application</th>
            <th className="px-4 py-3">Cloud</th>
            <th className="px-4 py-3">Sensitivity</th>
            <th className="px-4 py-3">Decision</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-sentinel-border/80">
          {matrix.map((item) => (
            <tr
              key={item.application_id}
              onClick={() => onSelect?.(item)}
              className="cursor-pointer transition hover:bg-sky-400/5"
            >
              <td className="px-4 py-3 font-semibold text-slate-100">{item.application}</td>
              <td className="px-4 py-3 text-slate-300">{item.cloud}</td>
              <td className="px-4 py-3 text-slate-300">{item.sensitivity}</td>
              <td className="px-4 py-3">
                <Badge className={decisionTone(item.decision)}>{titleCase(item.decision)}</Badge>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
