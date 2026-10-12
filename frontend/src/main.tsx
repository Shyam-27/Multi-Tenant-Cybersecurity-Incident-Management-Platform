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

export function App() {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem("sentinelops_token"));
  const [user, setUser] = useState<User | null>(null);
  const [tenant, setTenant] = useState<Tenant | null>(null);
  const [usersList, setUsersList] = useState<User[]>([]);
  const [loading, setLoading] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);
  const [authSuccess, setAuthSuccess] = useState<string | null>(null);
  const [authTab, setAuthTab] = useState<"login" | "register">("login");

  // Form states
  const [loginEmail, setLoginEmail] = useState("");
  const [loginPassword, setLoginPassword] = useState("");

  const [regOrgName, setRegOrgName] = useState("");
  const [regOrgSlug, setRegOrgSlug] = useState("");
  const [regName, setRegName] = useState("");
  const [regEmail, setRegEmail] = useState("");
  const [regPassword, setRegPassword] = useState("");

  // New user form for tenant admin
  const [newUserName, setNewUserName] = useState("");
  const [newUserEmail, setNewUserEmail] = useState("");
  const [newUserPassword, setNewUserPassword] = useState("");
  const [newUserRole, setNewUserRole] = useState("SECURITY_ANALYST");
  const [userActionMsg, setUserActionMsg] = useState<string | null>(null);

  // Password change
  const [currPassword, setCurrPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [pwChangeMsg, setPwChangeMsg] = useState<string | null>(null);

  // Authenticated API client
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
        // ignore logout network failure
      }
    }
    localStorage.removeItem("sentinelops_token");
    setToken(null);
    setUser(null);
    setTenant(null);
    setUsersList([]);
    if (customMsg) setAuthError(customMsg);
  };

  // Fetch user profile and tenant details
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
        console.error("Failed to load session", err);
      } finally {
        if (isMounted) setLoading(false);
      }
    }

    loadSession();
    return () => {
      isMounted = false;
    };
  }, [token]);

  // Load tenant users if admin
  const loadTenantUsers = async () => {
    if (!token || (user?.role !== "TENANT_ADMIN" && user?.role !== "SUPER_ADMIN")) return;
    try {
      const res = await apiCall("/users");
      if (res.ok) {
        const data = await res.json();
        setUsersList(data);
      }
    } catch (err) {
      console.error("Failed to load users", err);
    }
  };

  useEffect(() => {
    if (user && (user.role === "TENANT_ADMIN" || user.role === "SUPER_ADMIN")) {
      loadTenantUsers();
    }
  }, [user]);

  // Handle Login
  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    setAuthSuccess(null);
    setLoading(true);

    try {
      const res = await fetch(`${API_BASE}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: loginEmail, password: loginPassword }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || "Authentication failed");
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

  // Handle Registration
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
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || "Registration failed");
      }

      setAuthSuccess("Organization registered successfully. You may now log in.");
      setAuthTab("login");
      setLoginEmail(regEmail);
      setRegPassword("");
    } catch (err: any) {
      setAuthError(err.message || "Registration failed");
    } finally {
      setLoading(false);
    }
  };

  // Handle Create User inside Tenant
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

      setUserActionMsg("User created successfully!");
      setNewUserName("");
      setNewUserEmail("");
      setNewUserPassword("");
      await loadTenantUsers();
    } catch (err: any) {
      setUserActionMsg(`Error: ${err.message}`);
    }
  };

  // Toggle User Active Status
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
        alert(`Failed to update user: ${err.detail}`);
      }
    } catch (err: any) {
      alert(`Error updating user status: ${err.message}`);
    }
  };

  // Handle Change Password
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

  // View: Unauthenticated Login / Register Card
  if (!token || !user) {
    return (
      <main className="auth-container">
        <section className="auth-card" aria-labelledby="platform-title">
          <header className="auth-header">
            <p className="eyebrow">SentinelOps Security Platform</p>
            <h1 id="platform-title">Multi-Tenant Incident Ops</h1>
            <p className="description">Secure enterprise workspace for cybersecurity incident management.</p>
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
                {loading ? "Provisioning Organization..." : "Create Tenant Account"}
              </button>
            </form>
          )}

          <footer className="auth-footer">
            <span className="status-indicator">Backend Foundation v0.2.0 Online</span>
          </footer>
        </section>
      </main>
    );
  }

  // View: Authenticated Dashboard
  return (
    <div className="dashboard-layout">
      <header className="navbar">
        <div className="nav-brand">
          <span className="brand-icon">🛡️</span>
          <span className="brand-name">SentinelOps</span>
          <span className="tenant-badge">{tenant?.name || "Global"}</span>
        </div>

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
        <div className="dashboard-grid">
          {/* Identity & Tenant Overview */}
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

          {/* Change Password Card */}
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

        {/* Tenant Admin: User Management Panel */}
        {(user.role === "TENANT_ADMIN" || user.role === "SUPER_ADMIN") && (
          <div className="card full-width">
            <div className="card-header-flex">
              <h2>Tenant User Directory</h2>
              <span className="user-count">{usersList.length} user{usersList.length !== 1 ? "s" : ""}</span>
            </div>

            {userActionMsg && <div className="alert alert-info">{userActionMsg}</div>}

            {/* Add User Form */}
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

            {/* Users Table */}
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
                      <td>
                        <span className={`role-badge role-${u.role.toLowerCase()}`}>{u.role}</span>
                      </td>
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
      </main>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>
);
