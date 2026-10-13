import React, { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000/api/v1";

interface User {
  id: string;
  tenant_id: string | null;
  name: string;
  email: string;
  role: string;
  is_active: boolean;
  last_login_at: string | null;
  created_at: string;
}

interface Tenant {
  id: string;
  name: string;
  slug: string;
  status: string;
  is_active: boolean;
}

interface IncidentNote {
  id: string;
  tenant_id: string;
  incident_id: string;
  author_id: string;
  author_name: string | null;
  content: string;
  created_at: string;
}

interface Evidence {
  id: string;
  tenant_id: string;
  incident_id: string;
  uploaded_by_id: string;
  uploaded_by_name: string | null;
  filename: string;
  file_size_bytes: number;
  sha256_hash: string;
  mime_type: string;
  description: string;
  created_at: string;
}

interface AuditEventItem {
  id: string;
  tenant_id: string | null;
  actor_user_id: string | null;
  actor_user_name: string | null;
  actor_user_email: string | null;
  actor_type: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  outcome: string;
  occurred_at: string;
  request_id: string | null;
  source_ip: string | null;
  user_agent: string | null;
  details: Record<string, any>;
  previous_hash: string | null;
  event_hash: string | null;
}

interface Incident {
  id: string;
  tenant_id: string;
  title: string;
  description: string;
  category: string;
  severity: string;
  status: string;
  assigned_to_id: string | null;
  assigned_to_name: string | null;
  created_by_id: string;
  created_by_name: string | null;
  created_at: string;
  updated_at: string;
  resolved_at: string | null;
  notes: IncidentNote[];
  evidence: Evidence[];
}

interface IncidentMetrics {
  total: number;
  open: number;
  investigating: number;
  contained: number;
  resolved: number;
  closed: number;
  critical_and_high: number;
}

const CATEGORIES = [
  "ACCOUNT_COMPROMISE",
  "DATA_EXFILTRATION",
  "DENIAL_OF_SERVICE",
  "MALWARE",
  "PHISHING",
  "POLICY_VIOLATION",
  "RANSOMWARE",
  "UNAUTHORIZED_ACCESS",
  "OTHER",
];

const SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

const STATUS_TRANSITIONS: Record<string, string[]> = {
  OPEN: ["INVESTIGATING"],
  INVESTIGATING: ["CONTAINED", "RESOLVED"],
  CONTAINED: ["INVESTIGATING", "RESOLVED"],
  RESOLVED: ["INVESTIGATING", "CLOSED"],
  CLOSED: [],
};

export function App() {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem("sentinelops_token"));
  const [user, setUser] = useState<User | null>(null);
  const [tenant, setTenant] = useState<Tenant | null>(null);
  const [usersList, setUsersList] = useState<User[]>([]);
  const [loading, setLoading] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);
  const [authSuccess, setAuthSuccess] = useState<string | null>(null);
  const [authTab, setAuthTab] = useState<"login" | "register">("login");
  const [activeSection, setActiveSection] = useState<"incidents" | "users" | "audit" | "settings">("incidents");

  // Audit State
  const [auditEvents, setAuditEvents] = useState<AuditEventItem[]>([]);
  const [auditTotal, setAuditTotal] = useState(0);
  const [auditPage, setAuditPage] = useState(1);
  const [auditTotalPages, setAuditTotalPages] = useState(1);
  const [auditActionFilter, setAuditActionFilter] = useState("");
  const [auditOutcomeFilter, setAuditOutcomeFilter] = useState("");
  const [auditResourceTypeFilter, setAuditResourceTypeFilter] = useState("");
  const [auditVerification, setAuditVerification] = useState<{ is_valid: boolean; verified_count: number; details: string } | null>(null);
  const [auditLoading, setAuditLoading] = useState(false);

  // Auth Forms
  const [loginEmail, setLoginEmail] = useState("");
  const [loginPassword, setLoginPassword] = useState("");

  const [regOrgName, setRegOrgName] = useState("");
  const [regOrgSlug, setRegOrgSlug] = useState("");
  const [regName, setRegName] = useState("");
  const [regEmail, setRegEmail] = useState("");
  const [regPassword, setRegPassword] = useState("");

  // Incident state
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [metrics, setMetrics] = useState<IncidentMetrics | null>(null);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalIncidents, setTotalIncidents] = useState(0);

  // Incident Filters
  const [searchQuery, setSearchQuery] = useState("");
  const [filterStatus, setFilterStatus] = useState("");
  const [filterSeverity, setFilterSeverity] = useState("");
  const [filterCategory, setFilterCategory] = useState("");

  // Create Incident Modal
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newTitle, setNewTitle] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [newCategory, setNewCategory] = useState("OTHER");
  const [newSeverity, setNewSeverity] = useState("MEDIUM");
  const [newAssignedTo, setNewAssignedTo] = useState("");
  const [createIncidentError, setCreateIncidentError] = useState<string | null>(null);

  // New Note
  const [newNoteContent, setNewNoteContent] = useState("");
  const [noteSubmitting, setNoteSubmitting] = useState(false);

  // Evidence state
  const [evidenceFile, setEvidenceFile] = useState<File | null>(null);
  const [evidenceDescription, setEvidenceDescription] = useState("");
  const [evidenceUploading, setEvidenceUploading] = useState(false);
  const [evidenceError, setEvidenceError] = useState<string | null>(null);
  const [evidenceSuccess, setEvidenceSuccess] = useState<string | null>(null);

  // Team management
  const [newUserName, setNewUserName] = useState("");
  const [newUserEmail, setNewUserEmail] = useState("");
  const [newUserPassword, setNewUserPassword] = useState("");
  const [newUserRole, setNewUserRole] = useState("SECURITY_ANALYST");
  const [userActionMsg, setUserActionMsg] = useState<string | null>(null);

  // Password change
  const [currPassword, setCurrPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [pwChangeMsg, setPwChangeMsg] = useState<string | null>(null);

  // API Client
  const apiCall = async (endpoint: string, options: RequestInit = {}) => {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...(options.headers as Record<string, string>),
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const res = await fetch(`${API_BASE}${endpoint}`, { ...options, headers });
    if (res.status === 401) {
      handleLogout("Session expired. Please log in again.");
      throw new Error("Unauthorized");
    }
    return res;
  };

  const handleLogout = async (customMsg?: string) => {
    if (token) {
      try {
        await fetch(`${API_BASE}/auth/logout`, {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` },
        });
      } catch {
        // ignore network error
      }
    }
    localStorage.removeItem("sentinelops_token");
    setToken(null);
    setUser(null);
    setTenant(null);
    setUsersList([]);
    setIncidents([]);
    setSelectedIncident(null);
    if (customMsg) setAuthError(customMsg);
  };

  // Load Session
  useEffect(() => {
    if (!token) return;
    let isMounted = true;

    async function loadSession() {
      setLoading(true);
      try {
        const [userRes, tenantRes] = await Promise.all([
          apiCall("/auth/me"),
          apiCall("/tenants/me"),
        ]);

        if (userRes.ok && tenantRes.ok) {
          const userData = await userRes.json();
          const tenantData = await tenantRes.json();
          if (isMounted) {
            setUser(userData);
            setTenant(tenantData);
          }
        }
      } catch (err) {
        console.error("Session load failed", err);
      } finally {
        if (isMounted) setLoading(false);
      }
    }

    loadSession();
    return () => {
      isMounted = false;
    };
  }, [token]);

  // Load Users List
  const loadTenantUsers = async () => {
    if (!token) return;
    try {
      const res = await apiCall("/users");
      if (res.ok) {
        const data = await res.json();
        setUsersList(data);
      }
    } catch {
      // not allowed for viewers
    }
  };

  // Load Incidents and Metrics
  const loadIncidents = async () => {
    if (!token) return;
    try {
      const params = new URLSearchParams();
      params.set("page", page.toString());
      params.set("page_size", "10");
      if (searchQuery.trim()) params.set("search", searchQuery.trim());
      if (filterStatus) params.set("status", filterStatus);
      if (filterSeverity) params.set("severity", filterSeverity);
      if (filterCategory) params.set("category", filterCategory);

      const [incRes, metRes] = await Promise.all([
        apiCall(`/incidents?${params.toString()}`),
        apiCall("/incidents/metrics"),
      ]);

      if (incRes.ok) {
        const data = await incRes.json();
        setIncidents(data.items);
        setTotalPages(data.total_pages);
        setTotalIncidents(data.total);
      }

      if (metRes.ok) {
        const metData = await metRes.json();
        setMetrics(metData);
      }
    } catch (err) {
      console.error("Failed to load incidents", err);
    }
  };

  useEffect(() => {
    if (user) {
      loadIncidents();
      if (user.role === "TENANT_ADMIN" || user.role === "SUPER_ADMIN") {
        loadTenantUsers();
      }
    }
  }, [user, page, filterStatus, filterSeverity, filterCategory]);

  // Auth Handlers
  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    setLoading(true);

    try {
      const res = await fetch(`${API_BASE}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: loginEmail, password: loginPassword }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || "Authentication failed");
      }

      const data = await res.json();
      localStorage.setItem("sentinelops_token", data.access_token);
      setToken(data.access_token);
      setLoginPassword("");
    } catch (err: any) {
      setAuthError(err.message || "Login failed");
    } finally {
      setLoading(false);
    }
  };

  const handleRegisterSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    setAuthSuccess(null);
    setLoading(true);

    try {
      const res = await fetch(`${API_BASE}/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          organization_name: regOrgName,
          organization_slug: regOrgSlug.toLowerCase().trim(),
          name: regName,
          email: regEmail,
          password: regPassword,
        }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || "Registration failed");
      }

      setAuthSuccess("Organization registered. Please sign in.");
      setAuthTab("login");
      setLoginEmail(regEmail);
      setRegPassword("");
    } catch (err: any) {
      setAuthError(err.message || "Registration failed");
    } finally {
      setLoading(false);
    }
  };

  // Create Incident
  const handleCreateIncidentSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreateIncidentError(null);
    try {
      const payload: any = {
        title: newTitle,
        description: newDesc,
        category: newCategory,
        severity: newSeverity,
      };
      if (newAssignedTo) {
        payload.assigned_to_id = newAssignedTo;
      }

      const res = await apiCall("/incidents", {
        method: "POST",
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || "Failed to create incident");
      }

      const created = await res.json();
      setShowCreateModal(false);
      setNewTitle("");
      setNewDesc("");
      setNewAssignedTo("");
      await loadIncidents();
      setSelectedIncident(created);
    } catch (err: any) {
      setCreateIncidentError(err.message);
    }
  };

  // Select and Refresh Detail View
  const handleSelectIncident = async (id: string) => {
    try {
      const res = await apiCall(`/incidents/${id}`);
      if (res.ok) {
        const data = await res.json();
        setSelectedIncident(data);
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Update Incident Status / Severity / Assignment
  const handleUpdateIncidentStatus = async (newStatus: string) => {
    if (!selectedIncident) return;
    try {
      const res = await apiCall(`/incidents/${selectedIncident.id}`, {
        method: "PATCH",
        body: JSON.stringify({ status: newStatus }),
      });
      if (res.ok) {
        const updated = await res.json();
        setSelectedIncident(updated);
        await loadIncidents();
      } else {
        const err = await res.json().catch(() => ({}));
        alert(`Status update failed: ${err.detail}`);
      }
    } catch (err: any) {
      alert(`Error updating status: ${err.message}`);
    }
  };

  const handleUpdateIncidentSeverity = async (newSev: string) => {
    if (!selectedIncident) return;
    try {
      const res = await apiCall(`/incidents/${selectedIncident.id}`, {
        method: "PATCH",
        body: JSON.stringify({ severity: newSev }),
      });
      if (res.ok) {
        const updated = await res.json();
        setSelectedIncident(updated);
        await loadIncidents();
      }
    } catch (err: any) {
      alert(`Error updating severity: ${err.message}`);
    }
  };

  const handleUpdateIncidentAssignment = async (newAssigneeId: string) => {
    if (!selectedIncident) return;
    try {
      const res = await apiCall(`/incidents/${selectedIncident.id}`, {
        method: "PATCH",
        body: JSON.stringify({ assigned_to_id: newAssigneeId || null }),
      });
      if (res.ok) {
        const updated = await res.json();
        setSelectedIncident(updated);
        await loadIncidents();
      } else {
        const err = await res.json().catch(() => ({}));
        alert(`Assignment failed: ${err.detail}`);
      }
    } catch (err: any) {
      alert(`Error updating assignment: ${err.message}`);
    }
  };

  // Add Note
  const handleAddNoteSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedIncident || !newNoteContent.trim()) return;
    setNoteSubmitting(true);
    try {
      const res = await apiCall(`/incidents/${selectedIncident.id}/notes`, {
        method: "POST",
        body: JSON.stringify({ content: newNoteContent.trim() }),
      });
      if (res.ok) {
        setNewNoteContent("");
        await handleSelectIncident(selectedIncident.id);
      } else {
        const err = await res.json().catch(() => ({}));
        alert(`Failed to add note: ${err.detail}`);
      }
    } catch (err: any) {
      alert(`Error adding note: ${err.message}`);
    } finally {
      setNoteSubmitting(false);
    }
  };

  // Upload Evidence
  const handleEvidenceUploadSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedIncident || !evidenceFile) return;
    setEvidenceUploading(true);
    setEvidenceError(null);
    setEvidenceSuccess(null);

    const formData = new FormData();
    formData.append("file", evidenceFile);
    if (evidenceDescription.trim()) {
      formData.append("description", evidenceDescription.trim());
    }

    try {
      const headers: Record<string, string> = {};
      if (token) {
        headers["Authorization"] = `Bearer ${token}`;
      }
      const res = await fetch(`${API_BASE}/incidents/${selectedIncident.id}/evidence`, {
        method: "POST",
        headers,
        body: formData,
      });

      if (res.ok) {
        setEvidenceFile(null);
        setEvidenceDescription("");
        setEvidenceSuccess("Evidence artifact uploaded and verified successfully.");
        await handleSelectIncident(selectedIncident.id);
      } else {
        const err = await res.json().catch(() => ({}));
        setEvidenceError(err.detail || "Evidence upload failed.");
      }
    } catch (err: any) {
      setEvidenceError(err.message || "Network error uploading evidence.");
    } finally {
      setEvidenceUploading(false);
    }
  };

  // Download Evidence
  const handleEvidenceDownload = async (evidenceItem: Evidence) => {
    if (!selectedIncident) return;
    try {
      const headers: Record<string, string> = {};
      if (token) {
        headers["Authorization"] = `Bearer ${token}`;
      }
      const res = await fetch(`${API_BASE}/incidents/${selectedIncident.id}/evidence/${evidenceItem.id}/download`, {
        method: "GET",
        headers,
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        alert(`Download failed: ${err.detail || "Unable to download evidence"}`);
        return;
      }

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = evidenceItem.filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err: any) {
      alert(`Error downloading evidence: ${err.message}`);
    }
  };

  // Team Management Handlers
  const handleCreateUserSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setUserActionMsg(null);
    try {
      const res = await apiCall("/users", {
        method: "POST",
        body: JSON.stringify({
          name: newUserName,
          email: newUserEmail,
          password: newUserPassword,
          role: newUserRole,
        }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || "Failed to create user");
      }

      setUserActionMsg("User provisioned successfully!");
      setNewUserName("");
      setNewUserEmail("");
      setNewUserPassword("");
      await loadTenantUsers();
    } catch (err: any) {
      setUserActionMsg(`Error: ${err.message}`);
    }
  };

  const handleToggleUserStatus = async (targetUser: User) => {
    try {
      const res = await apiCall(`/users/${targetUser.id}`, {
        method: "PATCH",
        body: JSON.stringify({ is_active: !targetUser.is_active }),
      });
      if (res.ok) {
        await loadTenantUsers();
      } else {
        const err = await res.json().catch(() => ({}));
        alert(`Failed to update status: ${err.detail}`);
      }
    } catch (err: any) {
      alert(`Error: ${err.message}`);
    }
  };

  // Password Change Handler
  const handleChangePasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setPwChangeMsg(null);
    try {
      const res = await apiCall("/auth/change-password", {
        method: "POST",
        body: JSON.stringify({ current_password: currPassword, new_password: newPassword }),
      });
      if (res.ok) {
        setPwChangeMsg("Password updated successfully!");
        setCurrPassword("");
        setNewPassword("");
      } else {
        const err = await res.json().catch(() => ({}));
        setPwChangeMsg(`Error: ${err.detail || "Password change failed"}`);
      }
    } catch (err: any) {
      setPwChangeMsg(`Error: ${err.message}`);
    }
  };

  // Audit Log Handlers
  const loadAuditEvents = async () => {
    setAuditLoading(true);
    try {
      const params = new URLSearchParams();
      params.append("page", auditPage.toString());
      params.append("page_size", "15");
      if (auditActionFilter) params.append("action", auditActionFilter);
      if (auditOutcomeFilter) params.append("outcome", auditOutcomeFilter);
      if (auditResourceTypeFilter) params.append("resource_type", auditResourceTypeFilter);

      const res = await apiCall(`/audit-events?${params.toString()}`);
      if (res.ok) {
        const data = await res.json();
        setAuditEvents(data.items);
        setAuditTotal(data.total);
        setAuditTotalPages(data.total_pages);
      }
    } catch (err) {
      console.error("Failed to load audit events", err);
    } finally {
      setAuditLoading(false);
    }
  };

  const handleVerifyAuditChain = async () => {
    try {
      const res = await apiCall("/audit-events/verify-chain");
      if (res.ok) {
        const result = await res.json();
        setAuditVerification(result);
      } else {
        const err = await res.json().catch(() => ({}));
        alert(`Verification failed: ${err.detail || "Error verifying chain"}`);
      }
    } catch (err: any) {
      alert(`Error verifying audit chain: ${err.message}`);
    }
  };

  useEffect(() => {
    if (activeSection === "audit" && token) {
      loadAuditEvents();
    }
  }, [activeSection, auditPage, auditActionFilter, auditOutcomeFilter, auditResourceTypeFilter, token]);

  // View: Unauthenticated
  if (!token || !user) {
    return (
      <main className="auth-container">
        <section className="auth-card" aria-labelledby="platform-title">
          <header className="auth-header">
            <p className="eyebrow">SentinelOps Security Platform</p>
            <h1 id="platform-title">Incident Management SOC</h1>
            <p className="description">Enterprise multi-tenant cybersecurity incident response platform.</p>
          </header>

          <div className="tab-buttons" role="tablist">
            <button
              className={`tab-btn ${authTab === "login" ? "active" : ""}`}
              onClick={() => { setAuthTab("login"); setAuthError(null); }}
              type="button"
            >
              Log In
            </button>
            <button
              className={`tab-btn ${authTab === "register" ? "active" : ""}`}
              onClick={() => { setAuthTab("register"); setAuthError(null); }}
              type="button"
            >
              Register Organization
            </button>
          </div>

          {authError && <div className="alert alert-error">{authError}</div>}
          {authSuccess && <div className="alert alert-success">{authSuccess}</div>}

          {authTab === "login" ? (
            <form onSubmit={handleLoginSubmit} className="form-stack">
              <div className="form-group">
                <label htmlFor="login-email">Email Address</label>
                <input
                  id="login-email"
                  type="email"
                  required
                  placeholder="analyst@organization.com"
                  value={loginEmail}
                  onChange={(e) => setLoginEmail(e.target.value)}
                />
              </div>

              <div className="form-group">
                <label htmlFor="login-password">Password</label>
                <input
                  id="login-password"
                  type="password"
                  required
                  placeholder="••••••••••••"
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                />
              </div>

              <button type="submit" className="primary-btn" disabled={loading}>
                {loading ? "Authenticating..." : "Sign In to Platform"}
              </button>
            </form>
          ) : (
            <form onSubmit={handleRegisterSubmit} className="form-stack">
              <div className="form-row">
                <div className="form-group">
                  <label htmlFor="org-name">Organization Name</label>
                  <input
                    id="org-name"
                    type="text"
                    required
                    placeholder="Acme Security"
                    value={regOrgName}
                    onChange={(e) => setRegOrgName(e.target.value)}
                  />
                </div>
                <div className="form-group">
                  <label htmlFor="org-slug">Org Slug</label>
                  <input
                    id="org-slug"
                    type="text"
                    required
                    pattern="^[a-z0-9]+(?:-[a-z0-9]+)*$"
                    placeholder="acme-security"
                    value={regOrgSlug}
                    onChange={(e) => setRegOrgSlug(e.target.value.toLowerCase())}
                  />
                </div>
              </div>

              <div className="form-group">
                <label htmlFor="reg-name">Administrator Name</label>
                <input
                  id="reg-name"
                  type="text"
                  required
                  placeholder="Jane Doe"
                  value={regName}
                  onChange={(e) => setRegName(e.target.value)}
                />
              </div>

              <div className="form-group">
                <label htmlFor="reg-email">Administrator Email</label>
                <input
                  id="reg-email"
                  type="email"
                  required
                  placeholder="admin@acme-security.com"
                  value={regEmail}
                  onChange={(e) => setRegEmail(e.target.value)}
                />
              </div>

              <div className="form-group">
                <label htmlFor="reg-password">Password (≥12 chars, Upper, Lower, Number)</label>
                <input
                  id="reg-password"
                  type="password"
                  required
                  minLength={12}
                  placeholder="••••••••••••"
                  value={regPassword}
                  onChange={(e) => setRegPassword(e.target.value)}
                />
              </div>

              <button type="submit" className="primary-btn" disabled={loading}>
                {loading ? "Provisioning..." : "Create Tenant Account"}
              </button>
            </form>
          )}

          <footer className="auth-footer">
            <span className="status-indicator">Platform Phase 3 Online</span>
          </footer>
        </section>
      </main>
    );
  }

  const isViewer = user.role === "SECURITY_VIEWER";
  const nextValidStatuses = selectedIncident ? STATUS_TRANSITIONS[selectedIncident.status] || [] : [];

  // View: Authenticated Dashboard
  return (
    <div className="dashboard-layout">
      {/* Top Navbar */}
      <header className="navbar">
        <div className="nav-brand">
          <span className="brand-icon">🛡️</span>
          <span className="brand-name">SentinelOps</span>
          <span className="tenant-badge">{tenant?.name || "Global"}</span>
        </div>

        <nav className="nav-links">
          <button
            className={`nav-link ${activeSection === "incidents" ? "active" : ""}`}
            onClick={() => setActiveSection("incidents")}
          >
            Incidents
          </button>
          {(user.role === "TENANT_ADMIN" || user.role === "SUPER_ADMIN") && (
            <button
              className={`nav-link ${activeSection === "users" ? "active" : ""}`}
              onClick={() => setActiveSection("users")}
            >
              Team Directory
            </button>
          )}
          <button
            className={`nav-link ${activeSection === "audit" ? "active" : ""}`}
            onClick={() => setActiveSection("audit")}
          >
            Audit Trail
          </button>
          <button
            className={`nav-link ${activeSection === "settings" ? "active" : ""}`}
            onClick={() => setActiveSection("settings")}
          >
            Account Security
          </button>
        </nav>

        <div className="nav-user">
          <div className="user-info">
            <span className="user-name">{user.name}</span>
            <span className={`role-badge role-${user.role.toLowerCase()}`}>{user.role}</span>
          </div>
          <button onClick={() => handleLogout()} className="secondary-btn btn-sm">
            Log Out
          </button>
        </div>
      </header>

      <main className="dashboard-content">
        {/* SECTION 1: INCIDENTS */}
        {activeSection === "incidents" && (
          <div className="incident-view-stack">
            {/* Real Backend Incident Metrics */}
            {metrics && (
              <div className="metrics-grid">
                <div className="metric-card">
                  <span className="metric-title">Total Incidents</span>
                  <span className="metric-value">{metrics.total}</span>
                </div>
                <div className="metric-card">
                  <span className="metric-title">Open</span>
                  <span className="metric-value metric-open">{metrics.open}</span>
                </div>
                <div className="metric-card">
                  <span className="metric-title">Investigating</span>
                  <span className="metric-value metric-investigating">{metrics.investigating}</span>
                </div>
                <div className="metric-card">
                  <span className="metric-title">Critical & High</span>
                  <span className="metric-value metric-danger">{metrics.critical_and_high}</span>
                </div>
                <div className="metric-card">
                  <span className="metric-title">Contained</span>
                  <span className="metric-value metric-contained">{metrics.contained}</span>
                </div>
                <div className="metric-card">
                  <span className="metric-title">Resolved</span>
                  <span className="metric-value metric-resolved">{metrics.resolved}</span>
                </div>
              </div>
            )}

            {/* Filter & Action Bar */}
            <div className="action-bar">
              <div className="filter-controls">
                <input
                  type="text"
                  placeholder="Search title or description..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") { setPage(1); loadIncidents(); } }}
                  className="search-input"
                />
                <select value={filterStatus} onChange={(e) => { setFilterStatus(e.target.value); setPage(1); }}>
                  <option value="">All Statuses</option>
                  <option value="OPEN">OPEN</option>
                  <option value="INVESTIGATING">INVESTIGATING</option>
                  <option value="CONTAINED">CONTAINED</option>
                  <option value="RESOLVED">RESOLVED</option>
                  <option value="CLOSED">CLOSED</option>
                </select>
                <select value={filterSeverity} onChange={(e) => { setFilterSeverity(e.target.value); setPage(1); }}>
                  <option value="">All Severities</option>
                  {SEVERITIES.map((s) => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </select>
                <select value={filterCategory} onChange={(e) => { setFilterCategory(e.target.value); setPage(1); }}>
                  <option value="">All Categories</option>
                  {CATEGORIES.map((c) => (
                    <option key={c} value={c}>{c}</option>
                  ))}
                </select>
                <button type="button" onClick={() => { setPage(1); loadIncidents(); }} className="secondary-btn btn-sm">
                  Apply Filter
                </button>
              </div>

              {!isViewer && (
                <button
                  type="button"
                  onClick={() => setShowCreateModal(true)}
                  className="primary-btn btn-sm create-btn"
                >
                  + New Incident
                </button>
              )}
            </div>

            {/* Incidents Table */}
            <div className="card full-width">
              <div className="card-header-flex">
                <h2>Security Incidents</h2>
                <span className="user-count">{totalIncidents} incident{totalIncidents !== 1 ? "s" : ""}</span>
              </div>

              <div className="table-responsive">
                <table className="users-table">
                  <thead>
                    <tr>
                      <th>Title</th>
                      <th>Category</th>
                      <th>Severity</th>
                      <th>Status</th>
                      <th>Assigned Analyst</th>
                      <th>Reported By</th>
                      <th>Created</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {incidents.length === 0 ? (
                      <tr>
                        <td colSpan={8} className="empty-message">No incidents match the selected filters.</td>
                      </tr>
                    ) : (
                      incidents.map((inc) => (
                        <tr key={inc.id} className="interactive-row" onClick={() => handleSelectIncident(inc.id)}>
                          <td><strong>{inc.title}</strong></td>
                          <td><span className="category-tag">{inc.category}</span></td>
                          <td><span className={`badge sev-${inc.severity.toLowerCase()}`}>{inc.severity}</span></td>
                          <td><span className={`badge status-${inc.status.toLowerCase()}`}>{inc.status}</span></td>
                          <td>{inc.assigned_to_name || "Unassigned"}</td>
                          <td>{inc.created_by_name || "Unknown"}</td>
                          <td>{new Date(inc.created_at).toLocaleDateString()}</td>
                          <td>
                            <button
                              type="button"
                              className="secondary-btn btn-xs"
                              onClick={(e) => { e.stopPropagation(); handleSelectIncident(inc.id); }}
                            >
                              Inspect
                            </button>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>

              {/* Pagination Bar */}
              {totalPages > 1 && (
                <div className="pagination-bar">
                  <button
                    className="secondary-btn btn-xs"
                    disabled={page <= 1}
                    onClick={() => setPage(page - 1)}
                  >
                    Previous
                  </button>
                  <span className="page-indicator">Page {page} of {totalPages}</span>
                  <button
                    className="secondary-btn btn-xs"
                    disabled={page >= totalPages}
                    onClick={() => setPage(page + 1)}
                  >
                    Next
                  </button>
                </div>
              )}
            </div>
          </div>
        )}

        {/* SECTION 2: USERS DIRECTORY */}
        {activeSection === "users" && (user.role === "TENANT_ADMIN" || user.role === "SUPER_ADMIN") && (
          <div className="card full-width">
            <div className="card-header-flex">
              <h2>Tenant User Directory</h2>
              <span className="user-count">{usersList.length} user{usersList.length !== 1 ? "s" : ""}</span>
            </div>

            {userActionMsg && <div className="alert alert-info">{userActionMsg}</div>}

            <form onSubmit={handleCreateUserSubmit} className="add-user-bar">
              <input
                type="text"
                required
                placeholder="Full Name"
                value={newUserName}
                onChange={(e) => setNewUserName(e.target.value)}
              />
              <input
                type="email"
                required
                placeholder="User Email"
                value={newUserEmail}
                onChange={(e) => setNewUserEmail(e.target.value)}
              />
              <input
                type="password"
                required
                minLength={12}
                placeholder="Temp Password (≥12 chars)"
                value={newUserPassword}
                onChange={(e) => setNewUserPassword(e.target.value)}
              />
              <select value={newUserRole} onChange={(e) => setNewUserRole(e.target.value)}>
                <option value="SECURITY_ANALYST">SECURITY_ANALYST</option>
                <option value="SECURITY_VIEWER">SECURITY_VIEWER</option>
                <option value="TENANT_ADMIN">TENANT_ADMIN</option>
              </select>
              <button type="submit" className="primary-btn btn-sm">Provision User</button>
            </form>

            <div className="table-responsive">
              <table className="users-table">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Email</th>
                    <th>Role</th>
                    <th>Status</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {usersList.map((u) => (
                    <tr key={u.id}>
                      <td><strong>{u.name}</strong></td>
                      <td>{u.email}</td>
                      <td><span className={`role-badge role-${u.role.toLowerCase()}`}>{u.role}</span></td>
                      <td>
                        <span className={`badge ${u.is_active ? "badge-success" : "badge-inactive"}`}>
                          {u.is_active ? "Active" : "Deactivated"}
                        </span>
                      </td>
                      <td>
                        {u.id !== user.id ? (
                          <button
                            type="button"
                            onClick={() => handleToggleUserStatus(u)}
                            className="secondary-btn btn-xs"
                          >
                            {u.is_active ? "Deactivate" : "Activate"}
                          </button>
                        ) : (
                          <span className="self-tag">(Current user)</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* SECTION 3: ACCOUNT SETTINGS */}
        {activeSection === "settings" && (
          <div className="dashboard-grid">
            <div className="card">
              <h2>Organization & Identity</h2>
              <div className="meta-list">
                <div className="meta-item">
                  <span className="meta-label">Organization</span>
                  <span className="meta-value">{tenant?.name} ({tenant?.slug})</span>
                </div>
                <div className="meta-item">
                  <span className="meta-label">Status</span>
                  <span className="meta-value status-tag">{tenant?.status}</span>
                </div>
                <div className="meta-item">
                  <span className="meta-label">Email</span>
                  <span className="meta-value">{user.email}</span>
                </div>
                <div className="meta-item">
                  <span className="meta-label">Role Context</span>
                  <span className="meta-value">{user.role}</span>
                </div>
                <div className="meta-item">
                  <span className="meta-label">Account Active</span>
                  <span className="meta-value">{user.is_active ? "Yes" : "No"}</span>
                </div>
              </div>
            </div>

            <div className="card">
              <h2>Account Security</h2>
              {pwChangeMsg && <div className="alert alert-info">{pwChangeMsg}</div>}
              <form onSubmit={handleChangePasswordSubmit} className="form-stack">
                <div className="form-group">
                  <label>Current Password</label>
                  <input
                    type="password"
                    required
                    value={currPassword}
                    onChange={(e) => setCurrPassword(e.target.value)}
                  />
                </div>
                <div className="form-group">
                  <label>New Password (≥12 chars)</label>
                  <input
                    type="password"
                    required
                    minLength={12}
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                  />
                </div>
                <button type="submit" className="primary-btn btn-sm">Update Password</button>
              </form>
            </div>
          </div>
        )}

        {/* SECTION 4: AUDIT TRAIL & TAMPER-RESISTANT LOG VIEWER */}
        {activeSection === "audit" && (
          <div className="card full-width">
            <div className="card-header-flex">
              <div>
                <h2>Immutable Security Audit Trail</h2>
                <p className="field-hint" style={{ marginTop: "0.25rem" }}>
                  Cryptographically linked, append-only security events and administrative actions for {tenant?.name || "Tenant"}.
                </p>
              </div>
              <div className="audit-actions-bar">
                <button
                  type="button"
                  className="secondary-btn btn-xs"
                  onClick={handleVerifyAuditChain}
                  title="Verify SHA-256 cryptographic hash chain"
                >
                  🔗 Verify Hash Chain
                </button>
                <button
                  type="button"
                  className="secondary-btn btn-xs"
                  onClick={loadAuditEvents}
                  disabled={auditLoading}
                >
                  {auditLoading ? "Refreshing..." : "↻ Refresh"}
                </button>
              </div>
            </div>

            {/* Cryptographic Chain Verification Banner */}
            {auditVerification && (
              <div className={`alert ${auditVerification.is_valid ? "alert-success" : "alert-error"}`} style={{ marginTop: "1rem" }}>
                <strong>{auditVerification.is_valid ? "✓ Hash Chain Intact" : "⚠️ Cryptographic Tampering Detected"}</strong>
                <p style={{ margin: "0.25rem 0 0 0", fontSize: "0.85rem" }}>{auditVerification.details}</p>
              </div>
            )}

            {/* Audit Filters */}
            <div className="audit-filter-bar" style={{ marginTop: "1.25rem" }}>
              <div className="form-group">
                <label>Action</label>
                <input
                  type="text"
                  placeholder="Filter by action (e.g. LOGIN_SUCCESS)"
                  value={auditActionFilter}
                  onChange={(e) => { setAuditActionFilter(e.target.value); setAuditPage(1); }}
                />
              </div>

              <div className="form-group">
                <label>Outcome</label>
                <select
                  value={auditOutcomeFilter}
                  onChange={(e) => { setAuditOutcomeFilter(e.target.value); setAuditPage(1); }}
                >
                  <option value="">All Outcomes</option>
                  <option value="SUCCESS">SUCCESS</option>
                  <option value="FAILURE">FAILURE</option>
                  <option value="DENIED">DENIED</option>
                </select>
              </div>

              <div className="form-group">
                <label>Resource Type</label>
                <select
                  value={auditResourceTypeFilter}
                  onChange={(e) => { setAuditResourceTypeFilter(e.target.value); setAuditPage(1); }}
                >
                  <option value="">All Resources</option>
                  <option value="user">User</option>
                  <option value="incident">Incident</option>
                  <option value="incident_note">Incident Note</option>
                  <option value="evidence">Evidence</option>
                  <option value="tenant">Tenant</option>
                </select>
              </div>
            </div>

            {/* Audit Event Table */}
            <div className="table-responsive" style={{ marginTop: "1rem" }}>
              <table className="audit-table">
                <thead>
                  <tr>
                    <th>Timestamp (UTC)</th>
                    <th>Action</th>
                    <th>Actor</th>
                    <th>Resource</th>
                    <th>Outcome</th>
                    <th>Event Hash</th>
                    <th>Metadata & Details</th>
                  </tr>
                </thead>
                <tbody>
                  {auditEvents.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="empty-message">
                        {auditLoading ? "Loading audit trail..." : "No audit events match the query criteria."}
                      </td>
                    </tr>
                  ) : (
                    auditEvents.map((ev) => (
                      <tr key={ev.id}>
                        <td style={{ whiteSpace: "nowrap" }}>
                          <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
                            {new Date(ev.occurred_at).toLocaleString()}
                          </span>
                        </td>
                        <td>
                          <span className="audit-action-tag">
                            {ev.action}
                          </span>
                        </td>
                        <td>
                          <div>
                            <strong>{ev.actor_user_name || (ev.actor_type === "SYSTEM" ? "System" : "Anonymous")}</strong>
                            {ev.actor_user_email && (
                              <span style={{ display: "block", fontSize: "0.75rem", color: "var(--text-muted)" }}>
                                {ev.actor_user_email}
                              </span>
                            )}
                          </div>
                        </td>
                        <td>
                          <div>
                            <span className="category-tag">{ev.resource_type}</span>
                            {ev.resource_id && (
                              <span style={{ display: "block", fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.2rem" }}>
                                {ev.resource_id.length > 18 ? `${ev.resource_id.slice(0, 8)}...` : ev.resource_id}
                              </span>
                            )}
                          </div>
                        </td>
                        <td>
                          <span className={`badge ${ev.outcome === "SUCCESS" ? "badge-success" : ev.outcome === "DENIED" ? "sev-critical" : "badge-inactive"}`}>
                            {ev.outcome}
                          </span>
                        </td>
                        <td>
                          {ev.event_hash ? (
                            <code className="hash-code" title={ev.event_hash}>
                              {ev.event_hash.slice(0, 10)}...
                            </code>
                          ) : (
                            <span style={{ color: "var(--text-muted)" }}>—</span>
                          )}
                        </td>
                        <td>
                          <details className="audit-details-dropdown">
                            <summary style={{ cursor: "pointer", fontSize: "0.8rem", color: "var(--accent-blue)" }}>
                              View Metadata ({Object.keys(ev.details || {}).length} keys)
                            </summary>
                            <pre className="audit-details-pre">
                              {JSON.stringify(ev.details, null, 2)}
                            </pre>
                          </details>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {/* Audit Pagination Bar */}
            {auditTotalPages > 1 && (
              <div className="pagination-bar" style={{ marginTop: "1rem" }}>
                <button
                  className="secondary-btn btn-xs"
                  disabled={auditPage <= 1}
                  onClick={() => setAuditPage(auditPage - 1)}
                >
                  Previous
                </button>
                <span className="page-indicator">Page {auditPage} of {auditTotalPages} ({auditTotal} total events)</span>
                <button
                  className="secondary-btn btn-xs"
                  disabled={auditPage >= auditTotalPages}
                  onClick={() => setAuditPage(auditPage + 1)}
                >
                  Next
                </button>
              </div>
            )}
          </div>
        )}
      </main>

      {/* MODAL 1: CREATE INCIDENT */}
      {showCreateModal && (
        <div className="modal-overlay" onClick={() => setShowCreateModal(false)}>
          <div className="modal-card" onClick={(e) => e.stopPropagation()}>
            <header className="modal-header">
              <h2>Create Security Incident</h2>
              <button className="close-btn" onClick={() => setShowCreateModal(false)}>✕</button>
            </header>

            {createIncidentError && <div className="alert alert-error">{createIncidentError}</div>}

            <form onSubmit={handleCreateIncidentSubmit} className="form-stack">
              <div className="form-group">
                <label>Incident Title *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Unauthorized access to production database"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                />
              </div>

              <div className="form-row">
                <div className="form-group">
                  <label>Category</label>
                  <select value={newCategory} onChange={(e) => setNewCategory(e.target.value)}>
                    {CATEGORIES.map((c) => (
                      <option key={c} value={c}>{c}</option>
                    ))}
                  </select>
                </div>
                <div className="form-group">
                  <label>Severity</label>
                  <select value={newSeverity} onChange={(e) => setNewSeverity(e.target.value)}>
                    {SEVERITIES.map((s) => (
                      <option key={s} value={s}>{s}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="form-group">
                <label>Assign Lead Analyst (Optional)</label>
                <select value={newAssignedTo} onChange={(e) => setNewAssignedTo(e.target.value)}>
                  <option value="">Unassigned</option>
                  {usersList
                    .filter((u) => u.role === "SECURITY_ANALYST" || u.role === "TENANT_ADMIN")
                    .map((u) => (
                      <option key={u.id} value={u.id}>{u.name} ({u.role})</option>
                    ))}
                </select>
              </div>

              <div className="form-group">
                <label>Description & Investigation Findings</label>
                <textarea
                  rows={4}
                  placeholder="Provide incident indicators, affected assets, and timeline details..."
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                />
              </div>

              <div className="modal-footer">
                <button type="button" className="secondary-btn" onClick={() => setShowCreateModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="primary-btn">
                  Publish Incident
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* DRAWER / MODAL 2: INCIDENT DETAIL & INVESTIGATION NOTES */}
      {selectedIncident && (
        <div className="modal-overlay" onClick={() => setSelectedIncident(null)}>
          <div className="drawer-card" onClick={(e) => e.stopPropagation()}>
            <header className="modal-header">
              <div>
                <span className={`badge sev-${selectedIncident.severity.toLowerCase()}`}>
                  {selectedIncident.severity}
                </span>{" "}
                <span className={`badge status-${selectedIncident.status.toLowerCase()}`}>
                  {selectedIncident.status}
                </span>
                <h2 style={{ marginTop: "0.5rem" }}>{selectedIncident.title}</h2>
              </div>
              <button className="close-btn" onClick={() => setSelectedIncident(null)}>✕</button>
            </header>

            <div className="drawer-body">
              {/* Incident Metadata & Workflow Actions */}
              <div className="incident-meta-box">
                <div className="meta-grid">
                  <div>
                    <span className="meta-label">Category</span>
                    <p><strong>{selectedIncident.category}</strong></p>
                  </div>
                  <div>
                    <span className="meta-label">Reported By</span>
                    <p>{selectedIncident.created_by_name || "Unknown"}</p>
                  </div>
                  <div>
                    <span className="meta-label">Created At</span>
                    <p>{new Date(selectedIncident.created_at).toLocaleString()}</p>
                  </div>
                  <div>
                    <span className="meta-label">Resolved At</span>
                    <p>{selectedIncident.resolved_at ? new Date(selectedIncident.resolved_at).toLocaleString() : "Not Resolved"}</p>
                  </div>
                </div>

                {/* Workflow Transitions (Analyst & Admin only) */}
                {!isViewer && (
                  <div className="workflow-control-bar">
                    <div className="form-group inline-group">
                      <label>Status Transition:</label>
                      {nextValidStatuses.length > 0 ? (
                        <div className="status-btn-group">
                          {nextValidStatuses.map((st) => (
                            <button
                              key={st}
                              type="button"
                              onClick={() => handleUpdateIncidentStatus(st)}
                              className="secondary-btn btn-xs"
                            >
                              Transition to {st}
                            </button>
                          ))}
                        </div>
                      ) : (
                        <span className="status-terminal-label">Terminal Status (Closed)</span>
                      )}
                    </div>

                    <div className="form-group inline-group">
                      <label>Severity:</label>
                      <select
                        value={selectedIncident.severity}
                        onChange={(e) => handleUpdateIncidentSeverity(e.target.value)}
                        className="select-xs"
                      >
                        {SEVERITIES.map((s) => (
                          <option key={s} value={s}>{s}</option>
                        ))}
                      </select>
                    </div>

                    <div className="form-group inline-group">
                      <label>Assigned To:</label>
                      <select
                        value={selectedIncident.assigned_to_id || ""}
                        onChange={(e) => handleUpdateIncidentAssignment(e.target.value)}
                        className="select-xs"
                      >
                        <option value="">Unassigned</option>
                        {usersList
                          .filter((u) => u.role === "SECURITY_ANALYST" || u.role === "TENANT_ADMIN")
                          .map((u) => (
                            <option key={u.id} value={u.id}>{u.name}</option>
                          ))}
                      </select>
                    </div>
                  </div>
                )}

                <div className="description-box">
                  <span className="meta-label">Incident Description</span>
                  <p>{selectedIncident.description || "No description provided."}</p>
                </div>
              </div>

              {/* Investigation Notes & Timeline */}
              <div className="notes-section">
                <h3>Investigation History & Notes ({selectedIncident.notes.length})</h3>

                <div className="notes-timeline">
                  {selectedIncident.notes.length === 0 ? (
                    <p className="empty-message">No investigation notes logged yet.</p>
                  ) : (
                    selectedIncident.notes.map((note) => (
                      <div key={note.id} className="note-card">
                        <div className="note-header">
                          <span className="note-author">👤 {note.author_name || "Analyst"}</span>
                          <span className="note-time">{new Date(note.created_at).toLocaleString()}</span>
                        </div>
                        <p className="note-content">{note.content}</p>
                      </div>
                    ))
                  )}
                </div>

                {/* Add Note Form */}
                {!isViewer && (
                  <form onSubmit={handleAddNoteSubmit} className="add-note-form">
                    <textarea
                      rows={3}
                      required
                      placeholder="Append investigation notes, analysis findings, or containment actions..."
                      value={newNoteContent}
                      onChange={(e) => setNewNoteContent(e.target.value)}
                    />
                    <button type="submit" className="primary-btn btn-sm" disabled={noteSubmitting}>
                      {noteSubmitting ? "Adding..." : "Log Investigation Note"}
                    </button>
                  </form>
                )}
              </div>

              {/* Digital Evidence Management */}
              <div className="evidence-section">
                <h3>Digital Evidence & Forensic Artifacts ({selectedIncident.evidence?.length || 0})</h3>

                {evidenceError && <div className="alert alert-error">{evidenceError}</div>}
                {evidenceSuccess && <div className="alert alert-success">{evidenceSuccess}</div>}

                <div className="evidence-list">
                  {(!selectedIncident.evidence || selectedIncident.evidence.length === 0) ? (
                    <p className="empty-message">No digital evidence artifacts attached to this incident.</p>
                  ) : (
                    selectedIncident.evidence.map((ev) => (
                      <div key={ev.id} className="evidence-card">
                        <div className="evidence-header">
                          <div className="evidence-title-group">
                            <span className="evidence-icon">📦</span>
                            <div>
                              <strong>{ev.filename}</strong>
                              <span className="evidence-size">
                                ({(ev.file_size_bytes / 1024).toFixed(1)} KB)
                              </span>
                            </div>
                          </div>
                          <button
                            type="button"
                            className="secondary-btn btn-xs download-btn"
                            onClick={() => handleEvidenceDownload(ev)}
                            title="Download evidence securely"
                          >
                            ⬇ Download
                          </button>
                        </div>

                        {ev.description && <p className="evidence-desc">{ev.description}</p>}

                        <div className="evidence-meta-row">
                          <span className="evidence-hash">
                            SHA-256: <code>{ev.sha256_hash}</code>
                          </span>
                          <span className="evidence-uploader">
                            Uploaded by {ev.uploaded_by_name || "Analyst"} on {new Date(ev.created_at).toLocaleString()}
                          </span>
                        </div>
                      </div>
                    ))
                  )}
                </div>

                {/* Upload Form (Analyst & Admin only) */}
                {!isViewer && (
                  <form onSubmit={handleEvidenceUploadSubmit} className="evidence-upload-form">
                    <h4>Attach Evidence Artifact</h4>
                    <p className="field-hint">
                      Supported formats: PCAP, PCAPNG, ZIP, TAR, GZ, TXT, LOG, JSON, CSV (Max 10 MiB). Executable formats are blocked.
                    </p>
                    <div className="form-row">
                      <div className="form-group" style={{ flex: 1 }}>
                        <label>Select File</label>
                        <input
                          type="file"
                          required
                          onChange={(e) => setEvidenceFile(e.target.files?.[0] || null)}
                        />
                      </div>
                      <div className="form-group" style={{ flex: 2 }}>
                        <label>Description / Provenance Notes</label>
                        <input
                          type="text"
                          placeholder="e.g. Memory dump, Wireshark packet capture, firewall syslogs"
                          value={evidenceDescription}
                          onChange={(e) => setEvidenceDescription(e.target.value)}
                        />
                      </div>
                    </div>

                    <button
                      type="submit"
                      className="primary-btn btn-sm"
                      disabled={evidenceUploading || !evidenceFile}
                    >
                      {evidenceUploading ? "Verifying & Uploading..." : "Upload Evidence Artifact"}
                    </button>
                  </form>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>
);
