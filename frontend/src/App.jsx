import { useCallback, useEffect, useMemo, useState } from "react";
import AppShell from "./components/layout/AppShell.jsx";
import DecisionModal from "./components/security/DecisionModal.jsx";
import { ErrorBlock, LoadingBlock } from "./components/common/StateBlock.jsx";
import { useSimulation } from "./hooks/useSimulation.js";
import { Api, getToken, setToken } from "./services/api.js";
import { Enrollment, HostMappings, BehaviorReview } from "./pages/Operations.jsx";
import AuditLogs from "./pages/AuditLogs.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import Devices from "./pages/Devices.jsx";
import Incidents from "./pages/Incidents.jsx";
import Login from "./pages/Login.jsx";
import Organization from "./pages/Organization.jsx";
import Security from "./pages/Security.jsx";
import Resources from "./pages/Resources.jsx";
import SystemWorkflow from "./pages/SystemWorkflow.jsx";
import UserProfile from "./pages/UserProfile.jsx";
import Users from "./pages/Users.jsx";

export default function App() {
  const [page, setPage] = useState("Overview");
  const [currentUser, setCurrentUser] = useState(null);
  const [selectedUserId, setSelectedUserId] = useState(null);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [decision, setDecision] = useState(null);
  const operator = ["ADMIN", "SECURITY_ANALYST", "ANALYST"].includes(currentUser?.role?.trim().toUpperCase());
  const token = getToken();

  const loadAll = useCallback(async (preferredUserId, options = {}) => {
    if (!options.silent) setLoading(true);
    setError("");
    try {
      const [me, users, applications, events, organization, devices, health] = await Promise.all([
        Api.me(),
        Api.users(),
        Api.applications(),
        Api.events(),
        Api.organization().catch(() => null),
        Api.devices().catch(() => []),
        Api.health()
      ]);
      const targetId = preferredUserId || selectedUserId || me.id || users[0]?.id;
      const canUseSimulation = health.demo_mode && targetId === me.id;
      const telemetry = await Api.telemetry(targetId);
      const [selected, posture, risk, matrix, userEvents, riskHistory, simulationStatus] = await Promise.all([
        Api.user(targetId),
        Api.posture(targetId),
        telemetry.length ? Api.risk(targetId) : null,
        telemetry.length ? Api.accessMatrix(targetId) : [],
        Api.userEvents(targetId),
        Api.riskHistory(targetId),
        canUseSimulation ? Api.simulationStatus(targetId) : Promise.resolve(null)
      ]);
      const summaries = await Promise.all(users.map(async (user) => {
        if (user.id === targetId) return { user, risk, posture };
        try {
          const [userRisk, userPosture] = await Promise.all([Api.risk(user.id), Api.posture(user.id)]);
          return { user, risk: userRisk, posture: userPosture };
        } catch {
          return { user, risk: null, posture: null };
        }
      }));
      setCurrentUser(me);
      setSelectedUserId(targetId);
      setData({
        users,
        applications,
        organization,
        devices,
        events,
        userEvents,
        selected,
        currentUser: me,
        posture,
        risk,
        telemetry,
        matrix,
        canUseSimulation,
        simulationStatus,
        userSummaries: summaries.sort((a, b) => (b.risk?.risk_score || 0) - (a.risk?.risk_score || 0)),
        riskHistory: riskHistory.reverse()
      });
    } catch (err) {
      setError(err?.response?.data?.detail || "Unable to load CloudSentinel data");
      if (err?.response?.status === 401) {
        setToken(null);
        setCurrentUser(null);
      }
    } finally {
      if (!options.silent) setLoading(false);
    }
  }, [selectedUserId]);

  const simulation = useSimulation({ selectedUserId, refreshData: loadAll });

  useEffect(() => {
    if (!token) {
      setLoading(false);
      return;
    }
    loadAll();
  }, []);

  useEffect(() => {
    if (!token || !currentUser) return undefined;
    const timer = window.setInterval(() => {
      loadAll(selectedUserId, { silent: true });
    }, 15000);
    return () => window.clearInterval(timer);
  }, [token, currentUser, selectedUserId, loadAll]);

  async function finishLogin(result) {
    setToken(result.access_token);
    setCurrentUser(result.user);
    await loadAll(result.user.id);
  }

  async function handleLogin(username, password) {
    const result = await Api.login(username, password);
    if (!result.mfa_required) await finishLogin(result);
    return result;
  }

  async function handleMfaVerify(mfaToken, code) {
    const result = await Api.mfaVerify(mfaToken, code);
    await finishLogin(result);
    return result;
  }

  async function handleSelectUser(id) {
    setSelectedUserId(id);
    setPage("Security Posture");
    await loadAll(id);
  }

  async function handleDecisionSelect(item) {
    if (!selectedUserId) return;
    const result = await Api.checkAccess({
      user_id: selectedUserId,
      application_id: item.application_id,
      action: "READ"
    });
    setDecision(result);
  }

  async function handleCreateUser(payload) {
    await Api.createUser(payload);
    await loadAll(selectedUserId, { silent: true });
  }

  async function handleUpdateUser(id, payload) {
    await Api.updateUser(id, payload);
    await loadAll(id, { silent: true });
  }

  async function handleDisableUser(id) {
    await Api.disableUser(id);
    await loadAll(selectedUserId, { silent: true });
  }

  async function handleDeviceHeartbeat(deviceId) {
    await Api.heartbeatDevice(deviceId, { agent_version: "0.1.0" });
    await loadAll(selectedUserId, { silent: true });
  }

  async function handleHealthyPosture(deviceId) {
    await Api.submitDevicePosture(deviceId, {
      os: "Windows",
      os_version: "Windows 11 Enterprise 23H2",
      firewall_enabled: true,
      encryption_enabled: true,
      security_product_active: true,
      patch_state: "CURRENT"
    });
    await loadAll(selectedUserId, { silent: true });
  }

  const pageContent = useMemo(() => {
    if (!data) return null;
    const shared = { data, onSelectUser: handleSelectUser, onDecisionSelect: handleDecisionSelect };
    if (operator && page === "Agent Enrollment") return <Enrollment users={data.users} />;
    if (operator && page === "Host Mapping") return <HostMappings applications={data.applications} onSaved={() => loadAll(selectedUserId, { silent: true })} />;
    if (operator && page === "Behavior Review") return <BehaviorReview users={data.users} />;
    if (["Overview", "Security Posture", "How It Works"].includes(page) && !data.telemetry.length)
      return <section className="panel p-5"><h2>No telemetry yet</h2><p>Risk and access decisions will appear once telemetry is available for {data.selected.username}.</p></section>;
    if (page === "Account Security") return <Security />;
    if (page === "Organization") return <Organization data={data} />;
    if (page === "Users") return <Users operator={operator} {...shared} onCreateUser={handleCreateUser} onUpdateUser={handleUpdateUser} onDisableUser={handleDisableUser} />;
    if (page === "Devices") return <Devices data={data} onRefreshDevice={handleDeviceHeartbeat} onSubmitHealthyPosture={handleHealthyPosture} />;
    if (page === "Security Posture") return <UserProfile {...shared} />;
    if (page === "Resources") return <Resources data={data} />;
    if (page === "Incidents") return <Incidents events={data.events} />;
    if (page === "Audit Logs") return <AuditLogs events={data.events} />;
    if (page === "How It Works") return <SystemWorkflow {...shared} simulation={simulation} />;
    return <Dashboard {...shared} simulation={simulation} />;
  }, [data, operator, page, simulation]);

  if (!currentUser && !getToken()) return <Login onLogin={handleLogin} onMfaVerify={handleMfaVerify} />;

  return (
    <AppShell operator={operator} page={page} onNavigate={setPage} applications={data?.applications || []} organization={data?.organization}>
      {loading && <LoadingBlock />}
      {!loading && error && <ErrorBlock message={error} />}
      {!loading && !error && pageContent}
      <DecisionModal decision={decision} onClose={() => setDecision(null)} />
    </AppShell>
  );
}
