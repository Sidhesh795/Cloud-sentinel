import { RefreshCcw, ShieldCheck } from "lucide-react";
import { Badge } from "../components/common/Badge.jsx";
import { formatRelativeTime, riskTone } from "../utils/format.js";

function postureTone(status) {
  if (status === "HEALTHY") return "border-emerald-400/30 bg-emerald-500/10 text-emerald-300";
  if (status === "WARNING") return "border-amber-400/30 bg-amber-500/10 text-amber-300";
  if (status === "COMPROMISED") return "border-red-400/30 bg-red-500/10 text-red-300";
  return "border-slate-400/30 bg-slate-500/10 text-slate-300";
}

export default function Devices({ data, onRefreshDevice, onSubmitHealthyPosture }) {
  return (
    <section className="panel p-5">
      <div className="mb-4 flex items-start justify-between gap-4">
        <div>
          <div className="metric-label">Devices</div>
          <h2 className="mt-1 text-2xl font-bold text-white">Endpoint Inventory</h2>
        </div>
        <Badge className="border-sky-400/30 bg-sky-500/10 text-sky-300">{data.devices.length} Registered</Badge>
      </div>
      <div className="overflow-hidden rounded-lg border border-sentinel-border">
        <table className="min-w-full divide-y divide-sentinel-border text-sm">
          <thead className="bg-white/[0.03] text-left text-xs uppercase tracking-[0.12em] text-slate-400">
            <tr>
              <th className="px-4 py-3">Device</th>
              <th className="px-4 py-3">User</th>
              <th className="px-4 py-3">Platform</th>
              <th className="px-4 py-3">Agent</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Posture</th>
              <th className="px-4 py-3">Risk</th>
              <th className="px-4 py-3">Last Seen</th>
              <th className="px-4 py-3">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-sentinel-border/70">
            {data.devices.map((device) => (
              <tr key={device.device_id} className="text-slate-200">
                <td className="px-4 py-3">
                  <div className="font-semibold text-white">{device.device_name || device.device_id}</div>
                  <div className="text-xs text-slate-500">{device.hostname || device.device_id}</div>
                </td>
                <td className="px-4 py-3">
                  <div>{device.user_display_name || device.username || "Unassigned"}</div>
                  <div className="text-xs text-slate-500">{device.user_email}</div>
                </td>
                <td className="px-4 py-3">{device.platform || device.os} {device.platform_version || device.os_version}</td>
                <td className="px-4 py-3">{device.agent_version || "0.1.0"}</td>
                <td className="px-4 py-3"><Badge className="border-emerald-400/30 bg-emerald-500/10 text-emerald-300">{device.status}</Badge></td>
                <td className="px-4 py-3"><Badge className={postureTone(device.posture_status)}>{device.posture_status}</Badge></td>
                <td className="px-4 py-3"><Badge className={riskTone(device.risk_score > 70 ? "HIGH" : "LOW")}>Risk {device.risk_score ?? "--"}</Badge></td>
                <td className="px-4 py-3 text-slate-400">{formatRelativeTime(device.last_seen)}</td>
                <td className="px-4 py-3">
                  <div className="flex gap-2">
                    <button title="Send heartbeat" onClick={() => onRefreshDevice(device.device_id)} className="focus-ring rounded-md border border-sentinel-border p-2 text-slate-300 hover:bg-white/5">
                      <RefreshCcw className="h-4 w-4" />
                    </button>
                    <button title="Submit healthy posture" onClick={() => onSubmitHealthyPosture(device.device_id)} className="focus-ring rounded-md border border-sentinel-border p-2 text-slate-300 hover:bg-white/5">
                      <ShieldCheck className="h-4 w-4" />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
