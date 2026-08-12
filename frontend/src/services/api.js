import axios from "axios";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";
const TOKEN_KEY = "cloudsentinel_token";

export const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 12000
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem(TOKEN_KEY);
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export function setToken(token) {
  if (token) localStorage.setItem(TOKEN_KEY, token);
  else localStorage.removeItem(TOKEN_KEY);
}

export function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

export const Api = {
  health: () => api.get("/api/health").then((r) => r.data),
  login: (username, password) => api.post("/api/auth/login", { username, password }).then((r) => r.data),
  me: () => api.get("/api/auth/me").then((r) => r.data),
  users: () => api.get("/api/users").then((r) => r.data),
  user: (id) => api.get(`/api/users/${id}`).then((r) => r.data),
  posture: (id) => api.get(`/api/users/${id}/posture`).then((r) => r.data),
  risk: (id) => api.get(`/api/users/${id}/risk`).then((r) => r.data),
  riskHistory: (id) => api.get(`/api/users/${id}/risk-history`).then((r) => r.data),
  telemetry: (id) => api.get(`/api/users/${id}/telemetry`).then((r) => r.data),
  userEvents: (id) => api.get(`/api/users/${id}/events`).then((r) => r.data),
  accessMatrix: (id) => api.get(`/api/users/${id}/access-matrix`).then((r) => r.data),
  applications: () => api.get("/api/applications").then((r) => r.data),
  events: () => api.get("/api/events").then((r) => r.data),
  checkAccess: (payload) => api.post("/api/access/check", payload).then((r) => r.data),
  simulationStatus: (id) => api.get(`/api/simulation/status/${id}`).then((r) => r.data),
  simulateAttack: (user_id) => api.post("/api/simulation/attack", { user_id }).then((r) => r.data),
  resetSimulation: (user_id) => api.post("/api/simulation/reset", { user_id }).then((r) => r.data)
};
