import Header from "./Header.jsx";
import Sidebar from "./Sidebar.jsx";

export default function AppShell({ page, onNavigate, applications, children }) {
  return (
    <div className="flex min-h-screen bg-sentinel-bg text-slate-100">
      <Sidebar current={page} onNavigate={onNavigate} />
      <div className="min-w-0 flex-1">
        <Header applications={applications} />
        <main className="h-[calc(100vh-5rem)] overflow-y-auto p-5">{children}</main>
      </div>
    </div>
  );
}
