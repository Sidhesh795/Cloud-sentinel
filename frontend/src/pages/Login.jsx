import { ShieldCheck, UserCheck, KeyRound } from "lucide-react";
import { useState } from "react";

export default function Login({ onLogin }) {
  const [username, setUsername] = useState("developer01");
  const [password, setPassword] = useState("CloudDemo123!");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit(event) {
    event.preventDefault();
    setLoading(true);
    setError("");
    try {
      await onLogin(username.trim(), password);
    } catch (err) {
      setError(err?.response?.data?.detail || "Login failed");
    } finally {
      setLoading(false);
    }
  }

  function setDemoCredentials(user) {
    setUsername(user);
    setPassword("CloudDemo123!");
    setError("");
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <form onSubmit={submit} className="panel w-full max-w-md p-7">
        <div className="mb-7 flex items-center gap-3">
          <div className="rounded-lg border border-sky-300/25 bg-sky-400/10 p-3 text-sky-300">
            <ShieldCheck className="h-6 w-6" />
          </div>
          <div>
            <h1 className="text-2xl font-black tracking-[0.12em] text-white">CloudSentinel</h1>
            <p className="text-sm text-slate-400">AI-Powered Adaptive Zero Trust</p>
          </div>
        </div>

        <div className="mb-5 rounded-md border border-sky-500/20 bg-sky-500/10 p-3 text-xs text-sky-200">
          <div className="font-semibold mb-1 flex items-center gap-1.5 text-sky-300">
            <UserCheck className="h-3.5 w-3.5" />
            Quick Demo Profiles
          </div>
          <div className="mt-2 flex gap-2">
            <button
              type="button"
              onClick={() => setDemoCredentials("developer01")}
              className={`rounded px-2.5 py-1 text-xs font-medium transition ${
                username === "developer01"
                  ? "bg-sky-400 text-slate-950 font-bold"
                  : "bg-sky-950/60 text-sky-300 hover:bg-sky-900/60 border border-sky-400/30"
              }`}
            >
              developer01 (Nina Patel)
            </button>
            <button
              type="button"
              onClick={() => setDemoCredentials("admin01")}
              className={`rounded px-2.5 py-1 text-xs font-medium transition ${
                username === "admin01"
                  ? "bg-sky-400 text-slate-950 font-bold"
                  : "bg-sky-950/60 text-sky-300 hover:bg-sky-900/60 border border-sky-400/30"
              }`}
            >
              admin01 (Avery Shah)
            </button>
          </div>
        </div>

        <label className="metric-label" htmlFor="username">Username</label>
        <input
          id="username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          className="focus-ring mt-2 w-full rounded-md border border-sentinel-border bg-black/20 px-3 py-2.5 text-sm text-white"
        />
        <label className="metric-label mt-4 block" htmlFor="password">Password</label>
        <input
          id="password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Demo password"
          className="focus-ring mt-2 w-full rounded-md border border-sentinel-border bg-black/20 px-3 py-2.5 text-sm text-white"
        />
        {error && <div className="mt-4 rounded-md border border-red-400/25 bg-red-500/10 px-3 py-2 text-sm text-red-200">{error}</div>}
        <button
          disabled={loading}
          className="focus-ring mt-6 w-full rounded-md bg-sky-400 px-4 py-2.5 text-sm font-bold text-slate-950 transition hover:bg-sky-300 disabled:opacity-60"
        >
          {loading ? "Authenticating" : "Enter Control Center"}
        </button>
        <p className="mt-4 text-xs text-slate-500 flex items-center gap-1.5">
          <KeyRound className="h-3 w-3" /> Password for all demo accounts: <code className="text-slate-300">CloudDemo123!</code>
        </p>
      </form>
    </div>
  );
}
