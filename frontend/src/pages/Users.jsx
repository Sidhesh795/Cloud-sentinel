import { useState } from "react";
import { Ban, Eye, Plus, Save } from "lucide-react";
import { Badge } from "../components/common/Badge.jsx";
import { riskTone } from "../utils/format.js";

const blankUser = {
  username: "",
  password: "CloudDemo123!",
  email: "",
  display_name: "",
  role: "EMPLOYEE",
  status: "ACTIVE"
};

export default function Users({ data, onSelectUser, onCreateUser, onUpdateUser, onDisableUser }) {
  const [draft, setDraft] = useState(blankUser);
  const [editing, setEditing] = useState(null);

  function updateDraft(key, value) {
    setDraft((current) => ({ ...current, [key]: value }));
  }

  async function submitNew(event) {
    event.preventDefault();
    await onCreateUser(draft);
    setDraft(blankUser);
  }

  async function saveEdit(user) {
    await onUpdateUser(user.id, {
      display_name: editing.display_name,
      email: editing.email,
      role: editing.role,
      status: editing.status
    });
    setEditing(null);
  }

  return (
    <section className="grid gap-4 xl:grid-cols-[360px_1fr]">
      <form onSubmit={submitNew} className="panel p-5">
        <div className="metric-label">Admin</div>
        <h2 className="mt-1 text-2xl font-bold text-white">Add User</h2>
        <div className="mt-5 grid gap-3">
          <input className="focus-ring rounded-md border border-sentinel-border bg-sentinel-panel2 px-3 py-2 text-sm text-white" placeholder="Username" value={draft.username} onChange={(e) => updateDraft("username", e.target.value)} />
          <input className="focus-ring rounded-md border border-sentinel-border bg-sentinel-panel2 px-3 py-2 text-sm text-white" placeholder="Display name" value={draft.display_name} onChange={(e) => updateDraft("display_name", e.target.value)} />
          <input className="focus-ring rounded-md border border-sentinel-border bg-sentinel-panel2 px-3 py-2 text-sm text-white" placeholder="Email" value={draft.email} onChange={(e) => updateDraft("email", e.target.value)} />
          <select className="focus-ring rounded-md border border-sentinel-border bg-sentinel-panel2 px-3 py-2 text-sm text-white" value={draft.role} onChange={(e) => updateDraft("role", e.target.value)}>
            <option>EMPLOYEE</option>
            <option>DEVELOPER</option>
            <option>SECURITY_ANALYST</option>
            <option>ADMIN</option>
          </select>
          <button className="focus-ring inline-flex items-center justify-center gap-2 rounded-md bg-sky-500 px-3 py-2 text-sm font-bold text-white hover:bg-sky-400">
            <Plus className="h-4 w-4" />
            Create User
          </button>
        </div>
      </form>
      <section className="panel p-5">
        <div className="mb-4">
          <div className="metric-label">Users</div>
          <h2 className="mt-1 text-2xl font-bold text-white">Organization Identities</h2>
        </div>
        <div className="grid gap-3">
          {data.userSummaries.map((item) => {
            const user = item.user;
            const isEditing = editing?.id === user.id;
            return (
              <div key={user.id} className="panel-soft p-4">
                <div className="grid gap-3 lg:grid-cols-[1.2fr_1fr_auto] lg:items-center">
                  <div>
                    {isEditing ? (
                      <input className="focus-ring w-full rounded-md border border-sentinel-border bg-sentinel-panel px-3 py-2 text-sm text-white" value={editing.display_name} onChange={(e) => setEditing({ ...editing, display_name: e.target.value })} />
                    ) : (
                      <div className="font-bold text-white">{user.display_name}</div>
                    )}
                    <div className="text-sm text-slate-400">{user.username}</div>
                    <div className="mt-2 flex flex-wrap gap-2">
                      <Badge className="border-sky-400/30 bg-sky-500/10 text-sky-300">{user.role}</Badge>
                      <Badge className={user.status === "ACTIVE" ? "border-emerald-400/30 bg-emerald-500/10 text-emerald-300" : "border-amber-400/30 bg-amber-500/10 text-amber-300"}>{user.status || (user.is_active ? "ACTIVE" : "DISABLED")}</Badge>
                      <Badge className={riskTone(item.risk?.risk_level)}>{item.risk?.risk_score ?? "--"} {item.risk?.risk_level || "RISK"}</Badge>
                    </div>
                  </div>
                  <div className="grid gap-2">
                    {isEditing ? (
                      <>
                        <input className="focus-ring rounded-md border border-sentinel-border bg-sentinel-panel px-3 py-2 text-sm text-white" value={editing.email} onChange={(e) => setEditing({ ...editing, email: e.target.value })} />
                        <div className="grid grid-cols-2 gap-2">
                          <select className="focus-ring rounded-md border border-sentinel-border bg-sentinel-panel px-3 py-2 text-sm text-white" value={editing.role} onChange={(e) => setEditing({ ...editing, role: e.target.value })}>
                            <option>EMPLOYEE</option>
                            <option>DEVELOPER</option>
                            <option>SECURITY_ANALYST</option>
                            <option>ADMIN</option>
                          </select>
                          <select className="focus-ring rounded-md border border-sentinel-border bg-sentinel-panel px-3 py-2 text-sm text-white" value={editing.status} onChange={(e) => setEditing({ ...editing, status: e.target.value })}>
                            <option>ACTIVE</option>
                            <option>SUSPENDED</option>
                            <option>DISABLED</option>
                          </select>
                        </div>
                      </>
                    ) : (
                      <>
                        <div className="text-sm text-slate-300">{user.email}</div>
                        <div className="text-xs text-slate-500">Devices: {item.posture?.devices?.length || 0} / Tags: {item.posture?.security_tags?.length || 0} / Events tracked</div>
                      </>
                    )}
                  </div>
                  <div className="flex gap-2">
                    <button title="View identity" onClick={() => onSelectUser(user.id)} className="focus-ring rounded-md border border-sentinel-border p-2 text-slate-300 hover:bg-white/5">
                      <Eye className="h-4 w-4" />
                    </button>
                    {isEditing ? (
                      <button title="Save user" onClick={() => saveEdit(user)} className="focus-ring rounded-md border border-emerald-400/30 p-2 text-emerald-300 hover:bg-emerald-500/10">
                        <Save className="h-4 w-4" />
                      </button>
                    ) : (
                      <button title="Edit user" onClick={() => setEditing({ id: user.id, display_name: user.display_name, email: user.email, role: user.role?.toUpperCase?.() || user.role, status: user.status || (user.is_active ? "ACTIVE" : "DISABLED") })} className="focus-ring rounded-md border border-sentinel-border px-3 py-2 text-xs font-bold text-slate-300 hover:bg-white/5">
                        Edit
                      </button>
                    )}
                    <button title="Disable user" onClick={() => onDisableUser(user.id)} className="focus-ring rounded-md border border-red-400/30 p-2 text-red-300 hover:bg-red-500/10">
                      <Ban className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </section>
    </section>
  );
}
