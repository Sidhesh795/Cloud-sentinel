import { AlertTriangle, Loader2 } from "lucide-react";

export function LoadingBlock({ label = "Loading security data" }) {
  return (
    <div className="panel-soft flex min-h-28 items-center justify-center gap-3 text-sm text-slate-300">
      <Loader2 className="h-4 w-4 animate-spin text-sky-300" />
      {label}
    </div>
  );
}

export function ErrorBlock({ message = "Unable to load data" }) {
  return (
    <div className="panel-soft flex min-h-28 items-center justify-center gap-3 text-sm text-red-200">
      <AlertTriangle className="h-4 w-4" />
      {message}
    </div>
  );
}

export function EmptyBlock({ label = "No records available" }) {
  return (
    <div className="panel-soft flex min-h-28 items-center justify-center text-sm text-slate-400">
      {label}
    </div>
  );
}
