import { useMemo, useState } from "react";
import { Api } from "../services/api.js";

const ATTACK_STEPS = [
  "Analyzing endpoint...",
  "New device detected",
  "Location anomaly detected",
  "Suspicious behavior detected",
  "Data exfiltration detected",
  "Behavioral anomaly confirmed",
  "Risk score recalculated",
  "Zero Trust policies re-evaluated",
  "Critical resources restricted"
];

const RESET_STEPS = [
  "Restoring baseline telemetry...",
  "Revalidating device posture",
  "Normal behavior confirmed",
  "Zero Trust policies re-evaluated",
  "Demo reset complete"
];

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export function useSimulation({ selectedUserId, refreshData }) {
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState([]);
  const [status, setStatus] = useState(null);
  const [lastResult, setLastResult] = useState(null);
  const [beforeSnapshot, setBeforeSnapshot] = useState(null);

  async function revealSteps(steps, delay = 650) {
    setProgress([]);
    for (const step of steps) {
      setProgress((current) => [...current, step]);
      await sleep(delay);
    }
  }

  async function loadStatus(id = selectedUserId) {
    if (!id) return null;
    const next = await Api.simulationStatus(id);
    setStatus(next);
    return next;
  }

  async function runAttack(currentData) {
    if (!selectedUserId || running) return;
    setRunning(true);
    setBeforeSnapshot({
      risk: currentData?.risk,
      matrix: currentData?.matrix || []
    });
    try {
      const request = Api.simulateAttack(selectedUserId);
      await revealSteps(ATTACK_STEPS);
      const result = await request;
      setLastResult(result);
      await loadStatus(selectedUserId);
      await refreshData(selectedUserId, { silent: true });
    } finally {
      setRunning(false);
    }
  }

  async function reset() {
    if (!selectedUserId || running) return;
    setRunning(true);
    try {
      const request = Api.resetSimulation(selectedUserId);
      await revealSteps(RESET_STEPS, 520);
      const result = await request;
      setLastResult(result);
      await loadStatus(selectedUserId);
      await refreshData(selectedUserId, { silent: true });
      setBeforeSnapshot(null);
    } finally {
      setRunning(false);
    }
  }

  const phaseLabel = useMemo(() => {
    if (running) return "INCIDENT DETECTED";
    if (status?.state === "COMPROMISED") return "THREAT CONTAINED";
    return "SYSTEM PROTECTED";
  }, [running, status]);

  return {
    running,
    progress,
    status,
    lastResult,
    beforeSnapshot,
    phaseLabel,
    loadStatus,
    runAttack,
    reset
  };
}
