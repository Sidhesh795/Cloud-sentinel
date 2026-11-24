import { useEffect, useState } from "react";
import { Api } from "../services/api.js";

const input = "focus-ring rounded border border-sentinel-border bg-sentinel-panel2 px-3 py-2";
const button = "focus-ring rounded border border-sky-400/40 px-3 py-2 text-sky-200 disabled:opacity-50";

function message(error) {
  const detail = error.response?.data?.detail;
  if (Array.isArray(detail)) return detail.map(item => item.msg).join(". ");
  return typeof detail === "string" ? detail : "Request failed. Please try again.";
}

function Panel({ title, children }) {
  return <section className="panel space-y-5 p-5">
    <h2 className="text-2xl font-bold text-white">{title}</h2>{children}
  </section>;
}

function UserSelector({ users, value, onChange, disabled }) {
  return <label className="flex items-center gap-3">User
    <select className={input} value={value} disabled={disabled} onChange={e => onChange(Number(e.target.value))}>
      {users.map(user => <option key={user.id} value={user.id}>{user.username}</option>)}
    </select>
  </label>;
}

export function Enrollment({ users }) {
  const active = users.filter(user => user.is_active && user.status === "ACTIVE");
  const [selected, setSelected] = useState(null);
  const id = active.find(user => user.id === selected)?.id ?? active[0]?.id;
  const [ttl, setTtl] = useState("60");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function issue(event) {
    event.preventDefault();
    setBusy(true);
    setResult(null);
    setError("");
    try { setResult(await Api.enrollmentToken(id, Number(ttl))); }
    catch (err) { setError(message(err)); }
    finally { setBusy(false); }
  }
  return <Panel title="Agent enrollment">
    {active.length ? <form onSubmit={issue} className="flex flex-wrap items-end gap-4">
      <UserSelector users={active} value={id} disabled={busy} onChange={value => { setSelected(value); setResult(null); }} />
      <label>Valid for (minutes) <input className={input} type="number" required min="5" max="1440" value={ttl} onChange={e => setTtl(e.target.value)} /></label>
      <button className={button} disabled={busy}>Issue enrollment token</button>
    </form> : <p>No active users available for enrollment.</p>}
    {error && <p role="alert">{error}</p>}
    {result && result.user_id === id && <div className="panel-soft space-y-2 p-4">
      <label className="block">Single-use enrollment token
        <input className={input + " block w-full font-mono"} readOnly value={result.token} onFocus={e => e.target.select()} />
      </label>
      <p>Copy this token before leaving. It expires at {new Date(result.expires_at).toLocaleString()}.</p>
      <button className={button} onClick={() => setResult(null)}>Hide token</button>
    </div>}
  </Panel>;
}

function HostEditor({ app, onSaved }) {
  const [host, setHost] = useState(app.upstream_host || "");
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  async function save(event) {
    event.preventDefault();
    setBusy(true);
    setStatus("");
    try {
      await Api.mapHost(app.id, host.trim().toLowerCase() || null);
      await onSaved();
      setStatus("Mapping saved.");
    } catch (err) { setStatus(message(err)); }
    finally { setBusy(false); }
  }
  return <form onSubmit={save} className="panel-soft flex flex-wrap items-center gap-3 p-4">
    <label className="flex flex-1 flex-wrap items-center gap-3"><span className="min-w-36">{app.name}</span>
      <input className={input} value={host} placeholder="app.example.com" maxLength={255}
        disabled={busy} onChange={e => { setHost(e.target.value); setStatus(""); }} />
    </label>
    <button className={button} disabled={busy || host === (app.upstream_host || "")}>{host.trim() ? "Save host" : "Remove mapping"}</button>
    {status && <span role="status">{status}</span>}
  </form>;
}

export function HostMappings({ applications, onSaved }) {
  return <Panel title="Host mapping">
    {applications.length ? <><p>Enter the hostname the proxy protects. Clear a hostname to remove its mapping.</p>
      {applications.map(app => app.organization_id == null
        ? <div key={app.id} className="panel-soft p-4">{app.name} · Shared catalog · {app.upstream_host || "Unmapped"} (read only)</div>
        : <HostEditor key={app.id + ":" + (app.upstream_host || "")} app={app} onSaved={onSaved} />)}
    </> : <p>No applications available to map.</p>}
  </Panel>;
}

function Review({ id }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [reload, setReload] = useState(0);
  useEffect(() => {
    let current = true;
    setError("");
    Promise.all([Api.baseline(id), Api.flaggedSnapshots(id)])
      .then(([baseline, snapshots]) => { if (current) setData({ baseline, snapshots }); })
      .catch(err => { if (current) setError(message(err)); });
    return () => { current = false; };
  }, [id, reload]);
  async function review(snapshotId, verdict) {
    setError("");
    setBusy(true);
    try {
      await Api.feedback(snapshotId, verdict);
      setData(previous => ({ ...previous, snapshots: previous.snapshots.map(row => row.id === snapshotId ? { ...row, verdict } : row) }));
    } catch (err) { setError(message(err)); }
    finally { setBusy(false); }
  }
  return <>
    {error && <p role="alert">{error} <button className={button} onClick={() => setReload(n => n + 1)}>Refresh review</button></p>}
    {!data && !error && <p role="status">Loading baseline and snapshots…</p>}
    {data && <>
      <h3 className="text-lg font-semibold">Behavior baseline</h3>
      <p>{data.baseline.ready ? "Ready" : "Collecting samples"} · {data.baseline.samples} samples ({data.baseline.required} required)</p>
      <dl>{Object.entries(data.baseline.features).map(([name, value]) =>
        <div key={name} className="flex gap-4 border-b border-sentinel-border py-2"><dt>{name}</dt>
          <dd>{Array.isArray(value) ? value.join(", ") + " UTC" : `Median ${value.median} · Scale ${value.scale}`}</dd></div>)}</dl>
      <h3 className="text-lg font-semibold">Recent flagged snapshots</h3>
      {!data.snapshots.length && <p>No flagged live snapshots for this user.</p>}
      {data.snapshots.map(row => <article key={row.id} className="panel-soft space-y-3 p-4">
        <h4>{new Date(row.timestamp).toLocaleString()} · Behavior risk {row.behavior_risk ?? "unavailable"}</h4>
        {row.explanations.map(note => <p key={note}>{note}</p>)}
        <p role="status">Review outcome · {row.verdict?.replaceAll("_", " ") || "Unreviewed"}</p>
        <div className="flex gap-2">{["CONFIRMED", "FALSE_POSITIVE"].map(verdict =>
          <button key={verdict} className={button} disabled={busy || row.verdict === verdict} onClick={() => review(row.id, verdict)}>
            {verdict === "CONFIRMED" ? "Confirm anomaly" : "Mark false positive"}
          </button>)}</div>
      </article>)}
    </>}
  </>;
}

export function BehaviorReview({ users }) {
  const [selected, setSelected] = useState(null);
  const id = users.find(user => user.id === selected)?.id ?? users[0]?.id;
  return <Panel title="Behavior review">
    {id ? <><UserSelector users={users} value={id} onChange={setSelected} /><Review key={id} id={id} /></> : <p>No users available for review.</p>}
  </Panel>;
}
