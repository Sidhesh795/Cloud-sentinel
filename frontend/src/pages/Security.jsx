import { useEffect, useState } from "react";
import { Api } from "../services/api.js";

const input = "focus-ring mt-2 w-full rounded-md border border-sentinel-border bg-black/20 px-3 py-2.5 text-sm text-white";
const button = "focus-ring rounded-md bg-sky-400 px-4 py-2.5 text-sm font-bold text-slate-950 transition hover:bg-sky-300 disabled:opacity-60";

export default function Security() {
  const [status, setStatus] = useState(null);
  const [setup, setSetup] = useState(null);
  const [codes, setCodes] = useState(null);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const refresh = () => Api.mfaStatus().then(setStatus).catch(() => setError("Unable to load MFA status"));
  useEffect(() => { refresh(); }, []);

  async function run(action) {
    setBusy(true);
    setError("");
    try {
      await action();
      setCode("");
      setPassword("");
      await refresh();
    } catch (err) {
      setError(err?.response?.data?.detail || "Request failed");
    } finally {
      setBusy(false);
    }
  }

  const start = () => run(async () => setSetup(await Api.mfaSetup()));
  const enable = () => run(async () => {
    const result = await Api.mfaEnable(code.trim());
    setCodes(result.recovery_codes);
    setSetup(null);
  });
  const disable = () => run(async () => {
    await Api.mfaDisable(password, code.trim());
    setCodes(null);
  });

  if (!status) return <div className="panel-soft p-6 text-sm text-slate-300">{error || "Loading"}</div>;

  return (
    <div className="panel max-w-2xl space-y-5 p-6">
      <div>
        <h2 className="text-xl font-bold text-white">Two-factor authentication</h2>
        <p className="mt-1 text-sm text-slate-400">
          Status: <span className={status.enabled ? "text-emerald-300" : "text-amber-300"}>{status.enabled ? "Enabled" : "Not enabled"}</span>
          {status.enabled && ` · ${status.recovery_codes_remaining} recovery codes left`}
        </p>
      </div>
      {error && <div className="rounded-md border border-red-400/25 bg-red-500/10 px-3 py-2 text-sm text-red-200">{error}</div>}

      {codes && (
        <div className="rounded-md border border-amber-400/30 bg-amber-500/10 p-4">
          <div className="text-sm font-semibold text-amber-200">Save these recovery codes now. They are shown once and each works one time.</div>
          <div className="mt-3 grid grid-cols-2 gap-2 font-mono text-sm text-white">{codes.map((c) => <code key={c}>{c}</code>)}</div>
        </div>
      )}

      {!status.enabled && !setup && <button className={button} disabled={busy} onClick={start}>Set up authenticator app</button>}

      {!status.enabled && setup && (
        <div className="space-y-3 text-sm text-slate-300">
          <p>In your authenticator app (Google Authenticator, Microsoft Authenticator, Authy, 1Password), add an account with this key:</p>
          <code className="block break-all rounded-md bg-black/30 p-3 text-sky-200">{setup.secret}</code>
          <details className="text-xs text-slate-400"><summary className="cursor-pointer">Setup link (otpauth URI)</summary><code className="mt-2 block break-all">{setup.otpauth_uri}</code></details>
          <label className="metric-label block" htmlFor="enable-code">Enter the 6-digit code to confirm</label>
          <input id="enable-code" className={input} value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" />
          <button className={button} disabled={busy || code.trim().length < 6} onClick={enable}>Enable MFA</button>
        </div>
      )}

      {status.enabled && (
        <div className="space-y-3 border-t border-sentinel-border pt-5 text-sm text-slate-300">
          <div className="font-semibold text-white">Disable MFA</div>
          <input className={input} type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} />
          <input className={input} placeholder="Current code or recovery code" value={code} onChange={(e) => setCode(e.target.value)} autoComplete="one-time-code" />
          <button className={button} disabled={busy || !password || code.trim().length < 6} onClick={disable}>Disable MFA</button>
        </div>
      )}
    </div>
  );
}
