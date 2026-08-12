import { ShieldCheck } from "lucide-react";
import { useState } from "react";

export default function Login({ onLogin }) {
  const [username, setUsername] = useState("developer01");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit(event) {
    event.preventDefault();
    setLoading(true);
    setError("");
    try {
      await onLogin(username, password);
    } catch (err) {
      setError(err?.response?.data?.detail || "Login failed");
    } finally {
      setLoading(false);
    }
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
        <p className="mt-4 text-xs text-slate-500">Demo account: developer01</p>
      </form>
    </div>
  );
}
