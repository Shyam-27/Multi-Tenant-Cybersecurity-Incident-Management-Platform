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
  mfa_enabled?: boolean;
  last_login_at: string | null;
  created_at: string;
}

interface MFAStatus {
  mfa_enabled: boolean;
  enrolled_at: string | null;
  recovery_codes_remaining: number;
}

interface MFAEnrollData {
  secret: string;
  provisioning_uri: string;
  qr_code: string;
  qr_code_svg?: string;
  recovery_codes: string[];
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

interface IOC {
  id: string;
  tenant_id: string;
  type: string;
  value: string;
  normalized_value: string;
  verdict: string;
  severity: string;
  confidence_score: number;
  is_false_positive: boolean;
  source: string;
  first_seen: string;
  last_seen: string;
  last_enriched_at: string | null;
  raw_enrichment: Record<string, any>;
  tags: string[];
  description: string;
  created_at: string;
  updated_at: string;
}

interface Destination {
  id: string;
  tenant_id: string;
  name: string;
  destination_type: string;
  endpoint_url: string;
  is_active: boolean;
  subscribed_events: string[];
  retry_limit: number;
  timeout_seconds: number;
  created_at: string;
  updated_at: string;
}

interface WebhookDeliveryItem {
  id: string;
  tenant_id: string;
  destination_id: string;
  event_type: string;
  payload: Record<string, any>;
  status: string;
  http_status?: number | null;
  response_status_code?: number | null;
  error_message?: string | null;
  error_summary?: string | null;
  last_error_category?: string | null;
  is_terminal_failure?: boolean;
  next_retry_at?: string | null;
  attempt_count: number;
  latency_ms: number | null;
  created_at: string;
  completed_at: string | null;
}

interface Playbook {
  id: string;
  tenant_id: string;
  name: string;
  description: string;
  trigger_event?: string;
  trigger_type?: string;
  actions: string[];
  is_enabled: boolean;
  is_dry_run: boolean;
  requires_approval: boolean;
  trigger_conditions?: Record<string, any>;
  rule_version?: number;
  cooldown_seconds?: number;
  created_at: string;
  updated_at: string;
}

interface PlaybookApprovalItem {
  id: string;
  execution_id: string;
  status: string;
  requested_by_id: string;
  decided_by_id: string | null;
  decided_at: string | null;
  notes: string | null;
  created_at: string;
}

interface PlaybookExecutionItem {
  id: string;
  tenant_id: string;
  playbook_id: string;
  incident_id: string | null;
  triggered_by_id: string | null;
  trigger_source?: string;
  trigger_event_id?: string | null;
  trigger_reason?: string | null;
  status: string;
  is_dry_run: boolean;
  execution_log: any[];
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  approval: PlaybookApprovalItem | null;
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
  const [activeSection, setActiveSection] = useState<
    "incidents" | "threat-intel" | "webhooks" | "playbooks" | "users" | "audit" | "settings"
  >("incidents");

  // MFA Authentication & Challenge State
  const [mfaChallengeToken, setMfaChallengeToken] = useState<string | null>(null);
  const [mfaInputCode, setMfaInputCode] = useState("");
  const [mfaUseRecovery, setMfaUseRecovery] = useState(false);
  const [mfaSubmitting, setMfaSubmitting] = useState(false);
  const [mfaError, setMfaError] = useState<string | null>(null);

  // MFA Management State (Settings)
  const [mfaStatus, setMfaStatus] = useState<MFAStatus | null>(null);
  const [mfaLoading, setMfaLoading] = useState(false);
  const [mfaActionMsg, setMfaActionMsg] = useState<string | null>(null);
  const [showEnrollModal, setShowEnrollModal] = useState(false);
  const [enrollData, setEnrollData] = useState<MFAEnrollData | null>(null);
  const [confirmTotpCode, setConfirmTotpCode] = useState("");
  const [enrollError, setEnrollError] = useState<string | null>(null);
  const [enrollSubmitting, setEnrollSubmitting] = useState(false);

  // Disable MFA & Recovery Codes Regeneration Modal States
  const [showDisableMfaModal, setShowDisableMfaModal] = useState(false);
  const [disablePassword, setDisablePassword] = useState("");
  const [disableTotpCode, setDisableTotpCode] = useState("");
  const [disableError, setDisableError] = useState<string | null>(null);
  const [disableSubmitting, setDisableSubmitting] = useState(false);

  const [showRegenModal, setShowRegenModal] = useState(false);
  const [regenPassword, setRegenPassword] = useState("");
  const [regenTotpCode, setRegenTotpCode] = useState("");
  const [regenCodes, setRegenCodes] = useState<string[] | null>(null);
  const [regenError, setRegenError] = useState<string | null>(null);
  const [regenSubmitting, setRegenSubmitting] = useState(false);

  // Step-Up Verification Modal State (Live Playbooks)
  const [showStepUpModal, setShowStepUpModal] = useState(false);
  const [stepUpCode, setStepUpCode] = useState("");
  const [stepUpError, setStepUpError] = useState<string | null>(null);
  const [stepUpSubmitting, setStepUpSubmitting] = useState(false);
  const [pendingApprovalId, setPendingApprovalId] = useState<string | null>(null);

  // Threat Intel State
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [iocTotal, setIocTotal] = useState(0);
  const [iocPage, setIocPage] = useState(1);
  const [iocTotalPages, setIocTotalPages] = useState(1);
  const [iocSearch, setIocSearch] = useState("");
  const [iocTypeFilter, setIocTypeFilter] = useState("");
  const [iocVerdictFilter, setIocVerdictFilter] = useState("");
  const [iocLoading, setIocLoading] = useState(false);
  const [selectedIoc, setSelectedIoc] = useState<IOC | null>(null);
  const [showCreateIocModal, setShowCreateIocModal] = useState(false);
  const [newIocType, setNewIocType] = useState("IPV4");
  const [newIocValue, setNewIocValue] = useState("");
  const [newIocSeverity, setNewIocSeverity] = useState("MEDIUM");
  const [newIocDescription, setNewIocDescription] = useState("");
  const [newIocTags, setNewIocTags] = useState("");
  const [iocActionMsg, setIocActionMsg] = useState<string | null>(null);
  const [enrichingIocId, setEnrichingIocId] = useState<string | null>(null);

  // SIEM & Webhook Destinations State
  const [destinations, setDestinations] = useState<Destination[]>([]);
  const [destLoading, setDestLoading] = useState(false);
  const [deliveries, setDeliveries] = useState<WebhookDeliveryItem[]>([]);
  const [deliveriesLoading, setDeliveriesLoading] = useState(false);
  const [showCreateDestModal, setShowCreateDestModal] = useState(false);
  const [newDestName, setNewDestName] = useState("");
  const [newDestType, setNewDestType] = useState("SPLUNK_HEC");
  const [newDestUrl, setNewDestUrl] = useState("");
  const [newDestSecret, setNewDestSecret] = useState("");
  const [newDestEvents, setNewDestEvents] = useState<string[]>([
    "incident.created.critical",
    "incident.status.changed",
  ]);
  const [destActionMsg, setDestActionMsg] = useState<string | null>(null);
  const [testingDestId, setTestingDestId] = useState<string | null>(null);
  const [destTestResult, setDestTestResult] = useState<{ id: string; success: boolean; message: string } | null>(null);
  const [retryingDeliveryId, setRetryingDeliveryId] = useState<string | null>(null);
  const [asyncEnrichingIocId, setAsyncEnrichingIocId] = useState<string | null>(null);

  // Response Playbooks State
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [playbooksLoading, setPlaybooksLoading] = useState(false);
  const [executions, setExecutions] = useState<PlaybookExecutionItem[]>([]);
  const [executionsLoading, setExecutionsLoading] = useState(false);
  const [selectedPlaybookToTrigger, setSelectedPlaybookToTrigger] = useState<Playbook | null>(null);
  const [triggerIncidentId, setTriggerIncidentId] = useState("");
  const [triggerParamUserId, setTriggerParamUserId] = useState("");
  const [triggerParamTarget, setTriggerParamTarget] = useState("");
  const [triggerDryRun, setTriggerDryRun] = useState(true);
  const [playbookSubmitting, setPlaybookSubmitting] = useState(false);
  const [playbookActionMsg, setPlaybookActionMsg] = useState<string | null>(null);
  const [selectedExecutionDetails, setSelectedExecutionDetails] = useState<PlaybookExecutionItem | null>(null);

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
      if (data.mfa_required) {
        setMfaChallengeToken(data.mfa_token);
        setMfaInputCode("");
        setMfaError(null);
        return;
      }
      localStorage.setItem("sentinelops_token", data.access_token);
      setToken(data.access_token);
      setLoginPassword("");
    } catch (err: any) {
      setAuthError(err.message || "Login failed");
    } finally {
      setLoading(false);
    }
  };

  const handleMfaVerifyLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mfaChallengeToken) return;
    setMfaError(null);
    setMfaSubmitting(true);
    try {
      const payload = mfaUseRecovery
        ? { mfa_token: mfaChallengeToken, recovery_code: mfaInputCode.trim() }
        : { mfa_token: mfaChallengeToken, totp_code: mfaInputCode.trim() };
      const res = await fetch(`${API_BASE}/auth/mfa/verify-login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || "Invalid verification code");
      }
      const data = await res.json();
      localStorage.setItem("sentinelops_token", data.access_token);
      setToken(data.access_token);
      setMfaChallengeToken(null);
      setMfaInputCode("");
      setLoginPassword("");
    } catch (err: any) {
      setMfaError(err.message || "MFA verification failed");
    } finally {
      setMfaSubmitting(false);
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

  // MFA Management Handlers
  const loadMfaStatus = async () => {
    if (!token) return;
    try {
      const res = await apiCall("/auth/mfa/status");
      if (res.ok) {
        const data = await res.json();
        setMfaStatus(data);
      }
    } catch (err) {
      console.error("Failed to load MFA status", err);
    }
  };

  const handleStartMfaEnrollment = async () => {
    setMfaLoading(true);
    setMfaActionMsg(null);
    setEnrollError(null);
    setConfirmTotpCode("");
    try {
      const res = await apiCall("/auth/mfa/enroll", { method: "POST" });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || "Failed to initiate MFA enrollment");
      }
      const data = await res.json();
      setEnrollData(data);
      setShowEnrollModal(true);
    } catch (err: any) {
      setMfaActionMsg(`Error: ${err.message}`);
    } finally {
      setMfaLoading(false);
    }
  };

  const handleConfirmMfaEnrollment = async (e: React.FormEvent) => {
    e.preventDefault();
    setEnrollSubmitting(true);
    setEnrollError(null);
    try {
      const res = await apiCall("/auth/mfa/confirm-enroll", {
        method: "POST",
        body: JSON.stringify({ totp_code: confirmTotpCode.trim() }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || "Invalid TOTP verification code. Please check your clock and try again.");
      }
      setShowEnrollModal(false);
      setEnrollData(null);
      setConfirmTotpCode("");
      setMfaActionMsg("✓ Two-Factor Authentication has been successfully activated for your account!");
      await loadMfaStatus();
      if (user) setUser({ ...user, mfa_enabled: true });
    } catch (err: any) {
      setEnrollError(err.message || "Failed to confirm MFA enrollment");
    } finally {
      setEnrollSubmitting(false);
    }
  };

  const handleDisableMfa = async (e: React.FormEvent) => {
    e.preventDefault();
    setDisableSubmitting(true);
    setDisableError(null);
    try {
      const res = await apiCall("/auth/mfa/disable", {
        method: "POST",
        body: JSON.stringify({ password: disablePassword, totp_code: disableTotpCode.trim() }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || "Failed to disable MFA");
      }
      setShowDisableMfaModal(false);
      setDisablePassword("");
      setDisableTotpCode("");
      setMfaActionMsg("Two-Factor Authentication has been disabled.");
      await loadMfaStatus();
      if (user) setUser({ ...user, mfa_enabled: false });
    } catch (err: any) {
      setDisableError(err.message);
    } finally {
      setDisableSubmitting(false);
    }
  };

  const handleRegenerateCodes = async (e: React.FormEvent) => {
    e.preventDefault();
    setRegenSubmitting(true);
    setRegenError(null);
    try {
      const res = await apiCall("/auth/mfa/recovery-codes/regenerate", {
        method: "POST",
        body: JSON.stringify({ password: regenPassword, totp_code: regenTotpCode.trim() }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || "Failed to regenerate recovery codes");
      }
      const data = await res.json();
      setRegenCodes(data.recovery_codes);
      setRegenPassword("");
      setRegenTotpCode("");
      await loadMfaStatus();
    } catch (err: any) {
      setRegenError(err.message);
    } finally {
      setRegenSubmitting(false);
    }
  };

  const handleStepUpApproveSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!pendingApprovalId) return;
    setStepUpSubmitting(true);
    setStepUpError(null);
    try {
      const res = await apiCall(`/playbooks/executions/${pendingApprovalId}/approve`, {
        method: "POST",
        headers: { "X-MFA-Code": stepUpCode.trim() },
        body: JSON.stringify({ notes: "Approved with Step-Up MFA" }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || "Step-Up verification failed");
      }
      setShowStepUpModal(false);
      setStepUpCode("");
      setPendingApprovalId(null);
      await loadExecutions();
    } catch (err: any) {
      setStepUpError(err.message);
    } finally {
      setStepUpSubmitting(false);
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

  // Phase 6: Threat Intelligence Handlers
  const loadIocs = async () => {
    setIocLoading(true);
    try {
      const params = new URLSearchParams();
      params.append("page", iocPage.toString());
      params.append("page_size", "15");
      if (iocTypeFilter) params.append("ioc_type", iocTypeFilter);
      if (iocVerdictFilter) params.append("verdict", iocVerdictFilter);
      if (iocSearch) params.append("search", iocSearch);

      const res = await apiCall(`/iocs?${params.toString()}`);
      if (res.ok) {
        const data = await res.json();
        setIocs(data.items);
        setIocTotal(data.total);
        setIocTotalPages(data.pages || 1);
      }
    } catch (err) {
      console.error("Failed to load IOCs", err);
    } finally {
      setIocLoading(false);
    }
  };

  const handleCreateIocSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIocActionMsg(null);
    try {
      const tagsArr = newIocTags
        .split(",")
        .map((t) => t.trim())
        .filter((t) => Boolean(t));
      const res = await apiCall("/iocs", {
        method: "POST",
        body: JSON.stringify({
          type: newIocType,
          value: newIocValue.trim(),
          severity: newIocSeverity,
          description: newIocDescription.trim(),
          tags: tagsArr,
        }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || "Failed to create indicator of compromise");
      }
      setShowCreateIocModal(false);
      setNewIocValue("");
      setNewIocDescription("");
      setNewIocTags("");
      await loadIocs();
    } catch (err: any) {
      setIocActionMsg(`Error: ${err.message}`);
    }
  };

  const handleEnrichIoc = async (iocItem: IOC) => {
    setEnrichingIocId(iocItem.id);
    try {
      const res = await apiCall(`/iocs/${iocItem.id}/enrich`, { method: "POST" });
      if (res.ok) {
        const updated = await res.json();
        setIocs((prev) => prev.map((item) => (item.id === updated.id ? updated : item)));
        if (selectedIoc && selectedIoc.id === updated.id) {
          setSelectedIoc(updated);
        }
      } else {
        const err = await res.json().catch(() => ({}));
        alert(`Enrichment failed: ${err.detail || "Unknown error"}`);
      }
    } catch (err: any) {
      alert(`Enrichment error: ${err.message}`);
    } finally {
      setEnrichingIocId(null);
    }
  };

  const handleAsyncEnrichIoc = async (iocItem: IOC) => {
    setAsyncEnrichingIocId(iocItem.id);
    try {
      const res = await apiCall(`/iocs/${iocItem.id}/enrich-async`, {
        method: "POST",
        body: JSON.stringify({ force_refresh: true }),
      });
      if (res.ok) {
        alert("Enrichment background task enqueued! Results will update automatically.");
        setTimeout(() => {
          loadIocs();
        }, 1500);
      } else {
        const err = await res.json().catch(() => ({}));
        alert(`Background refresh failed: ${err.detail || "Unknown error"}`);
      }
    } catch (err: any) {
      alert(`Background refresh error: ${err.message}`);
    } finally {
      setAsyncEnrichingIocId(null);
    }
  };

  const handleToggleFalsePositive = async (iocItem: IOC) => {
    try {
      const res = await apiCall(`/iocs/${iocItem.id}`, {
        method: "PATCH",
        body: JSON.stringify({ is_false_positive: !iocItem.is_false_positive }),
      });
      if (res.ok) {
        const updated = await res.json();
        setIocs((prev) => prev.map((item) => (item.id === updated.id ? updated : item)));
        if (selectedIoc && selectedIoc.id === updated.id) {
          setSelectedIoc(updated);
        }
      }
    } catch (err: any) {
      alert(`Failed to update indicator: ${err.message}`);
    }
  };

  // Phase 6: SIEM & Webhook Destinations Handlers
  const loadDestinations = async () => {
    setDestLoading(true);
    try {
      const res = await apiCall("/destinations");
      if (res.ok) {
        const data = await res.json();
        setDestinations(data);
      }
    } catch (err) {
      console.error("Failed to load destinations", err);
    } finally {
      setDestLoading(false);
    }
  };

  const loadDeliveries = async () => {
    setDeliveriesLoading(true);
    try {
      const res = await apiCall("/destinations/deliveries/list?page=1&page_size=20");
      if (res.ok) {
        const data = await res.json();
        setDeliveries(data.items || []);
      }
    } catch (err) {
      console.error("Failed to load deliveries", err);
    } finally {
      setDeliveriesLoading(false);
    }
  };

  const handleRetryDelivery = async (deliveryId: string) => {
    setRetryingDeliveryId(deliveryId);
    try {
      const res = await apiCall(`/destinations/deliveries/${deliveryId}/retry`, {
        method: "POST",
      });
      if (res.ok) {
        await loadDeliveries();
      } else {
        const err = await res.json();
        alert(err.detail || "Failed to trigger delivery retry");
      }
    } catch (err) {
      console.error("Retry delivery failed", err);
    } finally {
      setRetryingDeliveryId(null);
    }
  };

  const handleCreateDestinationSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setDestActionMsg(null);
    try {
      const res = await apiCall("/destinations", {
        method: "POST",
        body: JSON.stringify({
          name: newDestName.trim(),
          destination_type: newDestType,
          endpoint_url: newDestUrl.trim(),
          secret_token: newDestSecret.trim() || undefined,
          subscribed_events: newDestEvents,
          is_active: true,
        }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || "Failed to create webhook destination");
      }
      setShowCreateDestModal(false);
      setNewDestName("");
      setNewDestUrl("");
      setNewDestSecret("");
      await loadDestinations();
    } catch (err: any) {
      setDestActionMsg(`Error: ${err.message}`);
    }
  };

  const handleTestDestination = async (destId: string) => {
    setTestingDestId(destId);
    setDestTestResult(null);
    try {
      const res = await apiCall(`/destinations/${destId}/test`, { method: "POST" });
      const data = await res.json();
      if (res.ok) {
        setDestTestResult({
          id: destId,
          success: data.status === "SUCCESS",
          message: `HTTP ${data.http_status} in ${data.latency_ms ? data.latency_ms.toFixed(1) : 0}ms - ${data.status}`,
        });
        await loadDeliveries();
      } else {
        setDestTestResult({
          id: destId,
          success: false,
          message: data.detail || "Test ping failed",
        });
      }
    } catch (err: any) {
      setDestTestResult({
        id: destId,
        success: false,
        message: err.message || "Network error",
      });
    } finally {
      setTestingDestId(null);
    }
  };

  const handleDeleteDestination = async (destId: string) => {
    if (!confirm("Are you sure you want to delete this notification destination?")) return;
    try {
      const res = await apiCall(`/destinations/${destId}`, { method: "DELETE" });
      if (res.ok) {
        setDestinations((prev) => prev.filter((d) => d.id !== destId));
      }
    } catch (err: any) {
      alert(`Failed to delete: ${err.message}`);
    }
  };

  // Phase 6: Response Playbook Handlers
  const loadPlaybooks = async () => {
    setPlaybooksLoading(true);
    try {
      const res = await apiCall("/playbooks");
      if (res.ok) {
        const data = await res.json();
        setPlaybooks(data);
      }
    } catch (err) {
      console.error("Failed to load playbooks", err);
    } finally {
      setPlaybooksLoading(false);
    }
  };

  const loadExecutions = async () => {
    setExecutionsLoading(true);
    try {
      const res = await apiCall("/playbooks/executions/list?page=1&page_size=20");
      if (res.ok) {
        const data = await res.json();
        setExecutions(data.items || []);
      }
    } catch (err) {
      console.error("Failed to load executions", err);
    } finally {
      setExecutionsLoading(false);
    }
  };

  const handleTriggerPlaybookSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedPlaybookToTrigger) return;
    setPlaybookSubmitting(true);
    setPlaybookActionMsg(null);
    try {
      const params: Record<string, any> = {};
      if (triggerParamUserId) params["user_id"] = triggerParamUserId.trim();
      if (triggerParamTarget) {
        params["hostname"] = triggerParamTarget.trim();
        params["ip"] = triggerParamTarget.trim();
      }

      const res = await apiCall(`/playbooks/${selectedPlaybookToTrigger.id}/execute`, {
        method: "POST",
        body: JSON.stringify({
          incident_id: triggerIncidentId || undefined,
          parameters: params,
          override_dry_run: triggerDryRun,
        }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || "Failed to trigger playbook");
      }
      const execution = await res.json();
      setSelectedPlaybookToTrigger(null);
      setTriggerParamUserId("");
      setTriggerParamTarget("");
      setTriggerIncidentId("");
      await loadExecutions();
      if (execution.status === "PENDING_APPROVAL") {
        alert("Playbook execution initiated! Dual authorization is required — an administrator must approve it.");
      }
    } catch (err: any) {
      setPlaybookActionMsg(`Error: ${err.message}`);
    } finally {
      setPlaybookSubmitting(false);
    }
  };

  const handleDecideApproval = async (executionId: string, approve: boolean) => {
    if (approve) {
      const targetExec = executions.find((ex) => ex.id === executionId);
      if (targetExec && !targetExec.is_dry_run && user?.mfa_enabled) {
        setPendingApprovalId(executionId);
        setStepUpCode("");
        setStepUpError(null);
        setShowStepUpModal(true);
        return;
      }
    }
    try {
      const endpoint = `/playbooks/executions/${executionId}/${approve ? "approve" : "reject"}`;
      const res = await apiCall(endpoint, {
        method: "POST",
        body: JSON.stringify({ notes: approve ? "Approved by SOC Admin" : "Rejected by SOC Admin" }),
      });
      if (res.ok) {
        await loadExecutions();
      } else {
        const err = await res.json().catch(() => ({}));
        if (res.status === 403 && (err.detail || "").toLowerCase().includes("step-up")) {
          setPendingApprovalId(executionId);
          setStepUpCode("");
          setStepUpError(null);
          setShowStepUpModal(true);
          return;
        }
        alert(`Decision error: ${err.detail || "Unable to process decision"}`);
      }
    } catch (err: any) {
      alert(`Decision error: ${err.message}`);
    }
  };

  useEffect(() => {
    if (!token) return;
    if (activeSection === "threat-intel") {
      loadIocs();
    } else if (activeSection === "webhooks") {
      loadDestinations();
      loadDeliveries();
    } else if (activeSection === "playbooks") {
      loadPlaybooks();
      loadExecutions();
    } else if (activeSection === "settings") {
      loadMfaStatus();
    }
  }, [activeSection, iocPage, iocTypeFilter, iocVerdictFilter, token]);

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
              onClick={() => { setAuthTab("login"); setAuthError(null); setMfaChallengeToken(null); }}
              type="button"
            >
              Log In
            </button>
            <button
              className={`tab-btn ${authTab === "register" ? "active" : ""}`}
              onClick={() => { setAuthTab("register"); setAuthError(null); setMfaChallengeToken(null); }}
              type="button"
            >
              Register Organization
            </button>
          </div>

          {authError && <div className="alert alert-error">{authError}</div>}
          {authSuccess && <div className="alert alert-success">{authSuccess}</div>}

          {mfaChallengeToken ? (
            <form onSubmit={handleMfaVerifyLoginSubmit} className="form-stack">
              <div style={{ textAlign: "center", marginBottom: "1rem" }}>
                <span style={{ fontSize: "2rem" }}>🔐</span>
                <h3 style={{ marginTop: "0.25rem", color: "var(--accent-blue)" }}>Two-Factor Authentication</h3>
                <p style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>
                  {mfaUseRecovery
                    ? "Enter an emergency 10-character backup recovery code"
                    : "Enter the 6-digit verification code from your authenticator app"}
                </p>
              </div>

              {mfaError && <div className="alert alert-error">{mfaError}</div>}

              <div className="form-group">
                <label>{mfaUseRecovery ? "Backup Recovery Code" : "6-Digit Security Code"}</label>
                <input
                  type="text"
                  required
                  autoFocus
                  placeholder={mfaUseRecovery ? "e.g. A1B2C-D3E4F" : "123456"}
                  value={mfaInputCode}
                  onChange={(e) => setMfaInputCode(e.target.value)}
                  maxLength={mfaUseRecovery ? 20 : 6}
                  style={{ textAlign: "center", fontSize: "1.25rem", letterSpacing: "0.2rem" }}
                />
              </div>

              <button type="submit" className="primary-btn" disabled={mfaSubmitting}>
                {mfaSubmitting ? "Verifying..." : "Verify & Complete Sign In"}
              </button>

              <div style={{ display: "flex", justifyContent: "space-between", marginTop: "0.75rem", fontSize: "0.8rem" }}>
                <button
                  type="button"
                  style={{ background: "none", border: "none", color: "var(--accent-blue)", cursor: "pointer", padding: 0 }}
                  onClick={() => { setMfaUseRecovery(!mfaUseRecovery); setMfaInputCode(""); setMfaError(null); }}
                >
                  {mfaUseRecovery ? "Use Authenticator App Code" : "Use Backup Recovery Code"}
                </button>
                <button
                  type="button"
                  style={{ background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer", padding: 0 }}
                  onClick={() => { setMfaChallengeToken(null); setMfaInputCode(""); setMfaError(null); }}
                >
                  ← Back to Login
                </button>
              </div>
            </form>
          ) : authTab === "login" ? (
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
          <button
            className={`nav-link ${activeSection === "threat-intel" ? "active" : ""}`}
            onClick={() => setActiveSection("threat-intel")}
          >
            Threat Intel
          </button>
          <button
            className={`nav-link ${activeSection === "webhooks" ? "active" : ""}`}
            onClick={() => setActiveSection("webhooks")}
          >
            SIEM & Webhooks
          </button>
          <button
            className={`nav-link ${activeSection === "playbooks" ? "active" : ""}`}
            onClick={() => setActiveSection("playbooks")}
          >
            Playbooks
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

            {/* Two-Factor Authentication (TOTP) Card */}
            <div className="card">
              <div className="card-header-flex">
                <div>
                  <h2>Two-Factor Authentication (TOTP)</h2>
                  <p className="field-hint" style={{ marginTop: "0.25rem" }}>
                    RFC 6238 time-based one-time password protection and privileged step-up authorization.
                  </p>
                </div>
                {mfaStatus?.mfa_enabled ? (
                  <span className="badge badge-success">✓ MFA ACTIVE</span>
                ) : (
                  <span className="badge badge-inactive">NOT ENROLLED</span>
                )}
              </div>

              {mfaActionMsg && <div className="alert alert-info" style={{ marginTop: "1rem" }}>{mfaActionMsg}</div>}

              {mfaStatus?.mfa_enabled ? (
                <div style={{ marginTop: "1rem" }}>
                  <div className="meta-list" style={{ marginBottom: "1.25rem" }}>
                    <div className="meta-item">
                      <span className="meta-label">Enrolled At</span>
                      <span className="meta-value">
                        {mfaStatus.enrolled_at ? new Date(mfaStatus.enrolled_at).toLocaleString() : "Active"}
                      </span>
                    </div>
                    <div className="meta-item">
                      <span className="meta-label">Backup Recovery Codes</span>
                      <span className="meta-value">{mfaStatus.recovery_codes_remaining} unused remaining</span>
                    </div>
                  </div>

                  <div style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap" }}>
                    <button
                      type="button"
                      className="secondary-btn btn-sm"
                      onClick={() => { setRegenCodes(null); setRegenError(null); setShowRegenModal(true); }}
                    >
                      🔄 Regenerate Recovery Codes
                    </button>
                    <button
                      type="button"
                      className="secondary-btn btn-sm"
                      style={{ color: "var(--accent-rose)", borderColor: "rgba(244, 63, 94, 0.4)" }}
                      onClick={() => { setDisableError(null); setShowDisableMfaModal(true); }}
                    >
                      Disable Two-Factor Auth
                    </button>
                  </div>
                </div>
              ) : (
                <div style={{ marginTop: "1rem" }}>
                  <p style={{ fontSize: "0.85rem", color: "var(--text-muted)", marginBottom: "1rem" }}>
                    Protect your administrative and analyst credentials with an authenticator app (Google Authenticator, Microsoft Authenticator, 1Password, or YubiKey). Privileged live response actions require verified MFA.
                  </p>
                  <button
                    type="button"
                    className="primary-btn btn-sm"
                    onClick={handleStartMfaEnrollment}
                    disabled={mfaLoading}
                  >
                    {mfaLoading ? "Initializing..." : "🛡️ Set Up Two-Factor Authentication"}
                  </button>
                </div>
              )}
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

        {/* SECTION 5: THREAT INTELLIGENCE & IOCS */}
        {activeSection === "threat-intel" && (
          <div className="card full-width">
            <div className="card-header-flex">
              <div>
                <h2>Threat Intelligence & Indicators of Compromise (IOC)</h2>
                <p className="field-hint" style={{ marginTop: "0.25rem" }}>
                  Tenant-scoped threat feed aggregator and indicator management with multi-provider reputation scoring.
                </p>
              </div>
              <div className="audit-actions-bar">
                {!isViewer && (
                  <button
                    type="button"
                    className="primary-btn btn-xs"
                    onClick={() => { setIocActionMsg(null); setShowCreateIocModal(true); }}
                  >
                    + Add Indicator
                  </button>
                )}
                <button
                  type="button"
                  className="secondary-btn btn-xs"
                  onClick={loadIocs}
                  disabled={iocLoading}
                >
                  {iocLoading ? "Refreshing..." : "↻ Refresh"}
                </button>
              </div>
            </div>

            {/* Filter & Search Bar */}
            <div className="audit-filter-bar" style={{ marginTop: "1.25rem" }}>
              <div className="form-group">
                <label>Search Indicator Value</label>
                <input
                  type="text"
                  placeholder="e.g. 198.51.100.42, malicious.com, sha256..."
                  value={iocSearch}
                  onChange={(e) => setIocSearch(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") { setIocPage(1); loadIocs(); } }}
                />
              </div>

              <div className="form-group">
                <label>Indicator Type</label>
                <select
                  value={iocTypeFilter}
                  onChange={(e) => { setIocTypeFilter(e.target.value); setIocPage(1); }}
                >
                  <option value="">All Types</option>
                  <option value="IPV4">IPv4 Address</option>
                  <option value="IPV6">IPv6 Address</option>
                  <option value="DOMAIN">Domain</option>
                  <option value="URL">URL</option>
                  <option value="SHA256">SHA-256 Hash</option>
                  <option value="MD5">MD5 Hash</option>
                </select>
              </div>

              <div className="form-group">
                <label>Verdict</label>
                <select
                  value={iocVerdictFilter}
                  onChange={(e) => { setIocVerdictFilter(e.target.value); setIocPage(1); }}
                >
                  <option value="">All Verdicts</option>
                  <option value="MALICIOUS">Malicious</option>
                  <option value="SUSPICIOUS">Suspicious</option>
                  <option value="BENIGN">Benign</option>
                  <option value="UNKNOWN">Unknown</option>
                </select>
              </div>
            </div>

            {/* IOC Table */}
            <div className="table-responsive" style={{ marginTop: "1rem" }}>
              <table className="audit-table">
                <thead>
                  <tr>
                    <th>Indicator Value</th>
                    <th>Type</th>
                    <th>Verdict</th>
                    <th>Confidence</th>
                    <th>Severity</th>
                    <th>False Positive</th>
                    <th>Last Enriched</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {iocs.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="empty-message">
                        {iocLoading ? "Loading threat indicators..." : "No indicators of compromise recorded yet."}
                      </td>
                    </tr>
                  ) : (
                    iocs.map((ioc) => (
                      <tr key={ioc.id}>
                        <td>
                          <div>
                            <strong style={{ fontFamily: "monospace", color: "#38bdf8" }}>{ioc.value}</strong>
                            {ioc.description && (
                              <p style={{ fontSize: "0.75rem", color: "var(--text-muted)", margin: "0.2rem 0 0 0" }}>
                                {ioc.description}
                              </p>
                            )}
                          </div>
                        </td>
                        <td>
                          <span className="category-tag">{ioc.type}</span>
                        </td>
                        <td>
                          <span className={`verdict-badge verdict-${ioc.verdict.toLowerCase()}`}>
                            {ioc.verdict}
                          </span>
                        </td>
                        <td>
                          <div className="confidence-bar-wrapper">
                            <div className="confidence-bar">
                              <div
                                className="confidence-fill"
                                style={{
                                  width: `${Math.round(ioc.confidence_score * 100)}%`,
                                  background:
                                    ioc.verdict === "MALICIOUS"
                                      ? "var(--accent-rose)"
                                      : ioc.verdict === "SUSPICIOUS"
                                      ? "var(--accent-amber)"
                                      : "var(--accent-emerald)",
                                }}
                              />
                            </div>
                            <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                              {Math.round(ioc.confidence_score * 100)}%
                            </span>
                          </div>
                        </td>
                        <td>
                          <span className={`badge sev-${ioc.severity.toLowerCase()}`}>
                            {ioc.severity}
                          </span>
                        </td>
                        <td>
                          <button
                            type="button"
                            className={`secondary-btn btn-xs ${ioc.is_false_positive ? "badge-inactive" : ""}`}
                            onClick={() => handleToggleFalsePositive(ioc)}
                            disabled={isViewer}
                          >
                            {ioc.is_false_positive ? "⚠️ Yes" : "No"}
                          </button>
                        </td>
                        <td>
                          <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                            {ioc.last_enriched_at ? new Date(ioc.last_enriched_at).toLocaleString() : "Never"}
                          </span>
                        </td>
                        <td>
                          <div style={{ display: "flex", gap: "0.35rem" }}>
                            <button
                              type="button"
                              className="secondary-btn btn-xs"
                              onClick={() => setSelectedIoc(ioc)}
                            >
                              Inspect
                            </button>
                            {!isViewer && (
                              <button
                                type="button"
                                className="secondary-btn btn-xs"
                                onClick={() => handleEnrichIoc(ioc)}
                                disabled={enrichingIocId === ioc.id}
                              >
                                {enrichingIocId === ioc.id ? "Enriching..." : "Enrich"}
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {/* IOC Pagination */}
            {iocTotalPages > 1 && (
              <div className="pagination-bar" style={{ marginTop: "1rem" }}>
                <button
                  className="secondary-btn btn-xs"
                  disabled={iocPage <= 1}
                  onClick={() => setIocPage(iocPage - 1)}
                >
                  Previous
                </button>
                <span className="page-indicator">Page {iocPage} of {iocTotalPages} ({iocTotal} indicators)</span>
                <button
                  className="secondary-btn btn-xs"
                  disabled={iocPage >= iocTotalPages}
                  onClick={() => setIocPage(iocPage + 1)}
                >
                  Next
                </button>
              </div>
            )}
          </div>
        )}

        {/* SECTION 6: SIEM & WEBHOOK DESTINATIONS */}
        {activeSection === "webhooks" && (
          <div className="card full-width">
            <div className="card-header-flex">
              <div>
                <h2>SIEM & Webhook Alerting Destinations</h2>
                <p className="field-hint" style={{ marginTop: "0.25rem" }}>
                  Real-time webhook notifications and SIEM ingestion pipeline for Splunk HEC, Elastic SIEM, MS Teams, and Slack.
                </p>
              </div>
              <div className="audit-actions-bar">
                {(user.role === "TENANT_ADMIN" || user.role === "SUPER_ADMIN") && (
                  <button
                    type="button"
                    className="primary-btn btn-xs"
                    onClick={() => { setDestActionMsg(null); setShowCreateDestModal(true); }}
                  >
                    + Register Destination
                  </button>
                )}
                <button
                  type="button"
                  className="secondary-btn btn-xs"
                  onClick={() => { loadDestinations(); loadDeliveries(); }}
                  disabled={destLoading}
                >
                  {destLoading ? "Refreshing..." : "↻ Refresh"}
                </button>
              </div>
            </div>

            {/* Test result banner */}
            {destTestResult && (
              <div
                className={`alert ${destTestResult.success ? "alert-success" : "alert-error"}`}
                style={{ marginTop: "1rem" }}
              >
                <strong>{destTestResult.success ? "✓ Test Ping Successful" : "✕ Test Ping Failed"}</strong>
                <p style={{ margin: "0.25rem 0 0 0", fontSize: "0.85rem" }}>{destTestResult.message}</p>
              </div>
            )}

            {/* Destination Cards */}
            <div className="destinations-grid">
              {destinations.length === 0 ? (
                <p className="empty-message">No SIEM or webhook destinations configured. Click &quot;Register Destination&quot; to configure one.</p>
              ) : (
                destinations.map((dest) => (
                  <div key={dest.id} className="dest-card">
                    <div className="dest-header">
                      <div>
                        <div className="dest-title">{dest.name}</div>
                        <span className="dest-type-tag">{dest.destination_type}</span>
                      </div>
                      <span className={`badge ${dest.is_active ? "badge-success" : "badge-inactive"}`}>
                        {dest.is_active ? "ACTIVE" : "INACTIVE"}
                      </span>
                    </div>

                    <div className="dest-url-box">
                      {dest.endpoint_url}
                    </div>

                    <div>
                      <span className="meta-label">Subscribed Events</span>
                      <div className="dest-events-row" style={{ marginTop: "0.3rem" }}>
                        {dest.subscribed_events.map((ev) => (
                          <span key={ev} className="event-pill">{ev}</span>
                        ))}
                      </div>
                    </div>

                    <div className="dest-actions">
                      <button
                        type="button"
                        className="secondary-btn btn-xs"
                        onClick={() => handleTestDestination(dest.id)}
                        disabled={testingDestId === dest.id}
                      >
                        {testingDestId === dest.id ? "Pinging..." : "⚡ Test Ping"}
                      </button>
                      {(user.role === "TENANT_ADMIN" || user.role === "SUPER_ADMIN") && (
                        <button
                          type="button"
                          className="secondary-btn btn-xs"
                          style={{ color: "var(--accent-rose)", borderColor: "rgba(244, 63, 94, 0.4)" }}
                          onClick={() => handleDeleteDestination(dest.id)}
                        >
                          Delete
                        </button>
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>

            {/* Delivery History */}
            <div style={{ marginTop: "2rem" }}>
              <h3>Recent Webhook Deliveries & Audit Logs</h3>
              <div className="table-responsive" style={{ marginTop: "0.75rem" }}>
                <table className="audit-table">
                  <thead>
                    <tr>
                      <th>Dispatched At</th>
                      <th>Event</th>
                      <th>HTTP Code</th>
                      <th>Category</th>
                      <th>Attempts</th>
                      <th>Status</th>
                      <th>Error Summary</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {deliveries.length === 0 ? (
                      <tr>
                        <td colSpan={8} className="empty-message">
                          {deliveriesLoading ? "Loading dispatch logs..." : "No recent webhook deliveries recorded."}
                        </td>
                      </tr>
                    ) : (
                      deliveries.map((del) => (
                        <tr key={del.id}>
                          <td>
                            <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                              {new Date(del.created_at).toLocaleString()}
                            </span>
                          </td>
                          <td>
                            <span className="category-tag">{del.event_type}</span>
                          </td>
                          <td>
                            <code>{del.response_status_code ?? del.http_status ?? "—"}</code>
                          </td>
                          <td>
                            <span style={{ fontSize: "0.75rem", fontFamily: "monospace" }}>
                              {del.last_error_category || "—"}
                            </span>
                          </td>
                          <td>
                            <span style={{ fontSize: "0.8rem" }}>
                              {del.attempt_count}
                              {del.is_terminal_failure ? " (Terminal)" : ""}
                            </span>
                          </td>
                          <td>
                            <span className={`badge ${del.status === "SUCCESS" ? "badge-success" : del.status === "PENDING" ? "badge-inactive" : del.status === "RETRYING" ? "sev-medium" : "sev-critical"}`}>
                              {del.status}
                            </span>
                          </td>
                          <td>
                            <span style={{ fontSize: "0.75rem", color: "var(--accent-rose)" }}>
                              {del.error_summary || del.error_message || "—"}
                            </span>
                          </td>
                          <td>
                            {del.status !== "SUCCESS" && (
                              <button
                                type="button"
                                className="secondary-btn btn-xs"
                                onClick={() => handleRetryDelivery(del.id)}
                                disabled={retryingDeliveryId === del.id}
                                style={{ padding: "0.2rem 0.5rem", fontSize: "0.75rem" }}
                              >
                                {retryingDeliveryId === del.id ? "Retrying..." : "🔄 Retry"}
                              </button>
                            )}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* SECTION 7: RESPONSE PLAYBOOKS */}
        {activeSection === "playbooks" && (
          <div className="card full-width">
            <div className="card-header-flex">
              <div>
                <h2>Automated Incident Response Playbooks</h2>
                <p className="field-hint" style={{ marginTop: "0.25rem" }}>
                  Execution engine with safety simulations (dry-run), credential revocation, network isolation, and dual-authorization approvals.
                </p>
              </div>
              <div className="audit-actions-bar">
                <button
                  type="button"
                  className="secondary-btn btn-xs"
                  onClick={() => { loadPlaybooks(); loadExecutions(); }}
                  disabled={playbooksLoading}
                >
                  {playbooksLoading ? "Refreshing..." : "↻ Refresh"}
                </button>
              </div>
            </div>

            {/* Pending Approvals Section */}
            {executions.filter((e) => e.status === "PENDING_APPROVAL").length > 0 && (
              <div className="approvals-banner" style={{ marginTop: "1.25rem" }}>
                <div className="approvals-header">
                  <div className="approvals-title">
                    <span>🛡️</span>
                    <span>
                      Pending Dual-Authorization Approvals ({executions.filter((e) => e.status === "PENDING_APPROVAL").length})
                    </span>
                  </div>
                </div>
                <p style={{ fontSize: "0.8rem", color: "var(--text-muted)", margin: "0 0 0.5rem 0" }}>
                  High-impact actions require review by a secondary administrator prior to production execution.
                </p>
                {executions
                  .filter((e) => e.status === "PENDING_APPROVAL")
                  .map((exec) => {
                    const pb = playbooks.find((p) => p.id === exec.playbook_id);
                    const isSelfRequest = exec.approval?.requested_by_id === user.id;
                    return (
                      <div key={exec.id} className="approval-card-item">
                        <div>
                          <strong>{pb?.name || "Response Playbook"}</strong>
                          <span style={{ display: "block", fontSize: "0.75rem", color: "var(--text-muted)" }}>
                            Execution ID: <code>{exec.id.slice(0, 8)}...</code> | Requested at {new Date(exec.created_at).toLocaleString()}
                          </span>
                        </div>
                        <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                          {isSelfRequest ? (
                            <span style={{ fontSize: "0.75rem", color: "var(--accent-amber)" }}>
                              ⚠️ Anti-Self-Approval: Awaiting peer admin
                            </span>
                          ) : (
                            <>
                              <button
                                type="button"
                                className="primary-btn btn-xs"
                                style={{ background: "var(--accent-emerald)" }}
                                onClick={() => handleDecideApproval(exec.id, true)}
                              >
                                ✓ Approve Execution
                              </button>
                              <button
                                type="button"
                                className="secondary-btn btn-xs"
                                style={{ color: "var(--accent-rose)" }}
                                onClick={() => handleDecideApproval(exec.id, false)}
                              >
                                ✕ Reject
                              </button>
                            </>
                          )}
                        </div>
                      </div>
                    );
                  })}
              </div>
            )}

            {/* Playbook Library */}
            <h3 style={{ marginTop: "1.5rem" }}>Playbook Library</h3>
            <div className="playbooks-grid">
              {playbooks.length === 0 ? (
                <p className="empty-message">No response playbooks configured.</p>
              ) : (
                playbooks.map((pb) => (
                  <div key={pb.id} className="playbook-card">
                    <div className="playbook-header">
                      <div>
                        <div className="playbook-name">{pb.name}</div>
                        <p className="playbook-desc">{pb.description}</p>
                      </div>
                    </div>

                    <div>
                      <span className="meta-label">Actions</span>
                      <div className="actions-badge-list" style={{ marginTop: "0.3rem" }}>
                        {pb.actions.map((act) => (
                          <span key={act} className="action-pill">{act}</span>
                        ))}
                      </div>
                    </div>

                    <div style={{ display: "flex", gap: "0.4rem", flexWrap: "wrap" }}>
                      <span className={pb.is_dry_run ? "dry-run-pill" : "action-pill"}>
                        {pb.is_dry_run ? "Simulation (Dry Run)" : "Live Execution"}
                      </span>
                      {pb.requires_approval && (
                        <span className="approval-pill">Dual Auth Required</span>
                      )}
                    </div>

                    <div style={{ marginTop: "auto", paddingTop: "0.75rem", borderTop: "1px solid rgba(255, 255, 255, 0.05)" }}>
                      {!isViewer && (
                        <button
                          type="button"
                          className="primary-btn btn-xs"
                          onClick={() => {
                            setSelectedPlaybookToTrigger(pb);
                            setTriggerDryRun(pb.is_dry_run);
                            setPlaybookActionMsg(null);
                          }}
                        >
                          ▶ Trigger Playbook
                        </button>
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>

            {/* Execution History */}
            <div style={{ marginTop: "2rem" }}>
              <h3>Execution Run History</h3>
              <div className="table-responsive" style={{ marginTop: "0.75rem" }}>
                <table className="audit-table">
                  <thead>
                    <tr>
                      <th>Initiated At</th>
                      <th>Playbook</th>
                      <th>Mode</th>
                      <th>Status</th>
                      <th>Completed</th>
                      <th>Log & Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {executions.length === 0 ? (
                      <tr>
                        <td colSpan={6} className="empty-message">
                          {executionsLoading ? "Loading executions..." : "No playbook executions recorded yet."}
                        </td>
                      </tr>
                    ) : (
                      executions.map((exec) => {
                        const pb = playbooks.find((p) => p.id === exec.playbook_id);
                        return (
                          <tr key={exec.id}>
                            <td>
                              <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                                {new Date(exec.created_at).toLocaleString()}
                              </span>
                            </td>
                            <td>
                              <strong>{pb?.name || exec.playbook_id.slice(0, 8)}</strong>
                            </td>
                            <td>
                              <span className={exec.is_dry_run ? "dry-run-pill" : "action-pill"}>
                                {exec.is_dry_run ? "DRY RUN" : "LIVE"}
                              </span>
                            </td>
                            <td>
                              <span
                                className={`badge ${
                                  exec.status === "SUCCESS"
                                    ? "badge-success"
                                    : exec.status === "PENDING_APPROVAL"
                                    ? "badge-inactive"
                                    : exec.status === "FAILED"
                                    ? "sev-critical"
                                    : "badge-inactive"
                                }`}
                              >
                                {exec.status}
                              </span>
                            </td>
                            <td>
                              <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                                {exec.completed_at ? new Date(exec.completed_at).toLocaleString() : "—"}
                              </span>
                            </td>
                            <td>
                              <button
                                type="button"
                                className="secondary-btn btn-xs"
                                onClick={() => setSelectedExecutionDetails(exec)}
                              >
                                View Log ({exec.execution_log?.length || 0} steps)
                              </button>
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </div>
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

      {/* MODAL 3: CREATE INDICATOR OF COMPROMISE */}
      {showCreateIocModal && (
        <div className="modal-overlay" onClick={() => setShowCreateIocModal(false)}>
          <div className="modal-card" onClick={(e) => e.stopPropagation()}>
            <header className="modal-header">
              <h2>Add Threat Indicator (IOC)</h2>
              <button className="close-btn" onClick={() => setShowCreateIocModal(false)}>✕</button>
            </header>

            {iocActionMsg && <div className="alert alert-error">{iocActionMsg}</div>}

            <form onSubmit={handleCreateIocSubmit} className="form-stack">
              <div className="form-row">
                <div className="form-group">
                  <label>Indicator Type *</label>
                  <select value={newIocType} onChange={(e) => setNewIocType(e.target.value)}>
                    <option value="IPV4">IPv4 Address</option>
                    <option value="IPV6">IPv6 Address</option>
                    <option value="DOMAIN">Domain Name</option>
                    <option value="URL">Full URL</option>
                    <option value="SHA256">SHA-256 Hash</option>
                    <option value="MD5">MD5 Hash</option>
                  </select>
                </div>
                <div className="form-group">
                  <label>Severity</label>
                  <select value={newIocSeverity} onChange={(e) => setNewIocSeverity(e.target.value)}>
                    <option value="LOW">LOW</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="HIGH">HIGH</option>
                    <option value="CRITICAL">CRITICAL</option>
                  </select>
                </div>
              </div>

              <div className="form-group">
                <label>Indicator Value *</label>
                <input
                  type="text"
                  required
                  placeholder={newIocType === "IPV4" ? "198.51.100.42" : newIocType === "DOMAIN" ? "c2-command.evil.org" : "Indicator value..."}
                  value={newIocValue}
                  onChange={(e) => setNewIocValue(e.target.value)}
                />
              </div>

              <div className="form-group">
                <label>Description & Intelligence Context</label>
                <input
                  type="text"
                  placeholder="e.g. Cobalt Strike Beacon C2 IP observed in phishing attachment"
                  value={newIocDescription}
                  onChange={(e) => setNewIocDescription(e.target.value)}
                />
              </div>

              <div className="form-group">
                <label>Tags (comma-separated)</label>
                <input
                  type="text"
                  placeholder="c2, cobalt-strike, apt29, ransomware"
                  value={newIocTags}
                  onChange={(e) => setNewIocTags(e.target.value)}
                />
              </div>

              <div className="modal-footer">
                <button type="button" className="secondary-btn" onClick={() => setShowCreateIocModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="primary-btn">
                  Record Indicator
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL 4: IOC DETAIL & MULTI-PROVIDER ENRICHMENT DRAWER */}
      {selectedIoc && (
        <div className="modal-overlay" onClick={() => setSelectedIoc(null)}>
          <div className="drawer-card" onClick={(e) => e.stopPropagation()}>
            <header className="modal-header">
              <div>
                <span className={`verdict-badge verdict-${selectedIoc.verdict.toLowerCase()}`}>
                  {selectedIoc.verdict}
                </span>{" "}
                <span className={`badge sev-${selectedIoc.severity.toLowerCase()}`}>
                  {selectedIoc.severity}
                </span>
                <h2 style={{ marginTop: "0.5rem", fontFamily: "monospace", color: "#38bdf8" }}>
                  {selectedIoc.value}
                </h2>
              </div>
              <button className="close-btn" onClick={() => setSelectedIoc(null)}>✕</button>
            </header>

            <div className="drawer-body">
              <div className="incident-meta-box">
                <div className="meta-grid">
                  <div>
                    <span className="meta-label">Type</span>
                    <p><strong>{selectedIoc.type}</strong></p>
                  </div>
                  <div>
                    <span className="meta-label">Normalized Value</span>
                    <p style={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{selectedIoc.normalized_value}</p>
                  </div>
                  <div>
                    <span className="meta-label">Confidence Score</span>
                    <p><strong>{Math.round(selectedIoc.confidence_score * 100)}%</strong></p>
                  </div>
                  <div>
                    <span className="meta-label">False Positive</span>
                    <p>{selectedIoc.is_false_positive ? "⚠️ Marked False Positive" : "No"}</p>
                  </div>
                </div>

                <div className="meta-grid" style={{ marginTop: "0.75rem" }}>
                  <div>
                    <span className="meta-label">First Seen</span>
                    <p>{new Date(selectedIoc.first_seen).toLocaleString()}</p>
                  </div>
                  <div>
                    <span className="meta-label">Last Seen</span>
                    <p>{new Date(selectedIoc.last_seen).toLocaleString()}</p>
                  </div>
                  <div>
                    <span className="meta-label">Last Enriched</span>
                    <p>{selectedIoc.last_enriched_at ? new Date(selectedIoc.last_enriched_at).toLocaleString() : "Never Enriched"}</p>
                  </div>
                  <div>
                    <span className="meta-label">Source</span>
                    <p>{selectedIoc.source}</p>
                  </div>
                </div>

                {!isViewer && (
                  <div style={{ marginTop: "1rem", display: "flex", gap: "0.5rem" }}>
                    <button
                      type="button"
                      className="primary-btn btn-sm"
                      onClick={() => handleEnrichIoc(selectedIoc)}
                      disabled={enrichingIocId === selectedIoc.id}
                    >
                      {enrichingIocId === selectedIoc.id ? "Querying Providers..." : "⚡ Enrich Indicator Now"}
                    </button>
                    <button
                      type="button"
                      className="secondary-btn btn-sm"
                      onClick={() => handleAsyncEnrichIoc(selectedIoc)}
                      disabled={asyncEnrichingIocId === selectedIoc.id}
                    >
                      {asyncEnrichingIocId === selectedIoc.id ? "Queuing..." : "🔄 Queue Background Refresh"}
                    </button>
                    <button
                      type="button"
                      className="secondary-btn btn-sm"
                      onClick={() => handleToggleFalsePositive(selectedIoc)}
                    >
                      {selectedIoc.is_false_positive ? "Unmark False Positive" : "Flag as False Positive"}
                    </button>
                  </div>
                )}
              </div>

              {/* Multi-provider enrichment cards */}
              <div style={{ marginTop: "1.5rem" }}>
                <h3>Threat Intelligence Provider Findings</h3>
                <div className="enrichment-grid">
                  {/* VirusTotal Provider */}
                  <div className="provider-card">
                    <div className="provider-header">
                      <span className="provider-name">🔍 VirusTotal v3</span>
                      <span className="dest-type-tag">Reputation</span>
                    </div>
                    {selectedIoc.raw_enrichment?.virustotal ? (
                      <div>
                        <div className="provider-stat-row">
                          <span>Malicious Detections:</span>
                          <strong style={{ color: "var(--accent-rose)" }}>
                            {selectedIoc.raw_enrichment.virustotal.malicious || 0}
                          </strong>
                        </div>
                        <div className="provider-stat-row">
                          <span>Suspicious Detections:</span>
                          <strong style={{ color: "var(--accent-amber)" }}>
                            {selectedIoc.raw_enrichment.virustotal.suspicious || 0}
                          </strong>
                        </div>
                        <div className="provider-stat-row">
                          <span>Harmless / Undetected:</span>
                          <strong style={{ color: "var(--accent-emerald)" }}>
                            {selectedIoc.raw_enrichment.virustotal.harmless || 0}
                          </strong>
                        </div>
                      </div>
                    ) : (
                      <p style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
                        No VirusTotal intelligence data cached or API key unconfigured.
                      </p>
                    )}
                  </div>

                  {/* AbuseIPDB Provider */}
                  <div className="provider-card">
                    <div className="provider-header">
                      <span className="provider-name">🌐 AbuseIPDB v2</span>
                      <span className="dest-type-tag">IP Intelligence</span>
                    </div>
                    {selectedIoc.raw_enrichment?.abuseipdb ? (
                      <div>
                        <div className="provider-stat-row">
                          <span>Abuse Confidence:</span>
                          <strong>
                            {selectedIoc.raw_enrichment.abuseipdb.abuseConfidenceScore || 0}%
                          </strong>
                        </div>
                        <div className="provider-stat-row">
                          <span>Total Reports:</span>
                          <strong>
                            {selectedIoc.raw_enrichment.abuseipdb.totalReports || 0}
                          </strong>
                        </div>
                        <div className="provider-stat-row">
                          <span>Country Code:</span>
                          <strong>{selectedIoc.raw_enrichment.abuseipdb.countryCode || "N/A"}</strong>
                        </div>
                      </div>
                    ) : (
                      <p style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
                        {selectedIoc.type.startsWith("IPV") ? "No AbuseIPDB intelligence data cached." : "AbuseIPDB only supports IP addresses."}
                      </p>
                    )}
                  </div>

                  {/* AlienVault OTX Provider */}
                  <div className="provider-card">
                    <div className="provider-header">
                      <span className="provider-name">👽 AlienVault OTX</span>
                      <span className="dest-type-tag">Community Pulses</span>
                    </div>
                    {selectedIoc.raw_enrichment?.otx ? (
                      <div>
                        <div className="provider-stat-row">
                          <span>Threat Pulses:</span>
                          <strong>{selectedIoc.raw_enrichment.otx.pulse_count || 0}</strong>
                        </div>
                        <div className="provider-stat-row">
                          <span>Associated Malware:</span>
                          <strong>{selectedIoc.raw_enrichment.otx.malware_families?.length || 0} families</strong>
                        </div>
                      </div>
                    ) : (
                      <p style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
                        No AlienVault OTX community pulses recorded for this indicator.
                      </p>
                    )}
                  </div>
                </div>
              </div>

              {/* Raw JSON details */}
              <div style={{ marginTop: "1.5rem" }}>
                <details className="audit-details-dropdown" style={{ maxWidth: "100%" }}>
                  <summary style={{ cursor: "pointer", fontSize: "0.85rem", color: "var(--accent-blue)" }}>
                    Raw Enrichment Response Details
                  </summary>
                  <pre className="audit-details-pre" style={{ maxHeight: "250px" }}>
                    {JSON.stringify(selectedIoc.raw_enrichment || {}, null, 2)}
                  </pre>
                </details>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* MODAL 5: REGISTER SIEM WEBHOOK DESTINATION */}
      {showCreateDestModal && (
        <div className="modal-overlay" onClick={() => setShowCreateDestModal(false)}>
          <div className="modal-card" onClick={(e) => e.stopPropagation()}>
            <header className="modal-header">
              <h2>Register Webhook / SIEM Destination</h2>
              <button className="close-btn" onClick={() => setShowCreateDestModal(false)}>✕</button>
            </header>

            {destActionMsg && <div className="alert alert-error">{destActionMsg}</div>}

            <form onSubmit={handleCreateDestinationSubmit} className="form-stack">
              <div className="form-group">
                <label>Destination Name *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Corporate Splunk HEC, SOC Slack Alerts"
                  value={newDestName}
                  onChange={(e) => setNewDestName(e.target.value)}
                />
              </div>

              <div className="form-row">
                <div className="form-group">
                  <label>Destination Type *</label>
                  <select value={newDestType} onChange={(e) => setNewDestType(e.target.value)}>
                    <option value="SPLUNK_HEC">Splunk HEC (HTTP Event Collector)</option>
                    <option value="ELASTIC_SIEM">Elastic SIEM / Elasticsearch</option>
                    <option value="MS_TEAMS">Microsoft Teams Webhook</option>
                    <option value="SLACK">Slack Incoming Webhook</option>
                    <option value="CUSTOM_WEBHOOK">Custom Generic Webhook</option>
                  </select>
                </div>
                <div className="form-group">
                  <label>Auth Secret / Token (Optional)</label>
                  <input
                    type="password"
                    placeholder="••••••••••••"
                    value={newDestSecret}
                    onChange={(e) => setNewDestSecret(e.target.value)}
                  />
                </div>
              </div>

              <div className="form-group">
                <label>Endpoint URL (Public HTTPS) *</label>
                <input
                  type="url"
                  required
                  placeholder="https://siem.corporate.net:8088/services/collector/event"
                  value={newDestUrl}
                  onChange={(e) => setNewDestUrl(e.target.value)}
                />
                <p className="field-hint">
                  SSRF Protection: Requests to private IP spaces (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), loopback, or cloud metadata (169.254.169.254) are strictly blocked.
                </p>
              </div>

              <div className="form-group">
                <label>Subscribed Events</label>
                <div style={{ display: "flex", flexDirection: "column", gap: "0.4rem", marginTop: "0.25rem" }}>
                  {[
                    "incident.created.critical",
                    "incident.status.changed",
                    "ioc.malicious.detected",
                    "playbook.execution.completed",
                  ].map((evt) => (
                    <label key={evt} style={{ display: "flex", alignItems: "center", gap: "0.5rem", fontSize: "0.8rem", textTransform: "none" }}>
                      <input
                        type="checkbox"
                        checked={newDestEvents.includes(evt)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setNewDestEvents([...newDestEvents, evt]);
                          } else {
                            setNewDestEvents(newDestEvents.filter((item) => item !== evt));
                          }
                        }}
                      />
                      <code>{evt}</code>
                    </label>
                  ))}
                </div>
              </div>

              <div className="modal-footer">
                <button type="button" className="secondary-btn" onClick={() => setShowCreateDestModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="primary-btn">
                  Register Destination
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL 6: TRIGGER PLAYBOOK EXECUTION */}
      {selectedPlaybookToTrigger && (
        <div className="modal-overlay" onClick={() => setSelectedPlaybookToTrigger(null)}>
          <div className="modal-card" onClick={(e) => e.stopPropagation()}>
            <header className="modal-header">
              <div>
                <h2>Trigger Playbook: {selectedPlaybookToTrigger.name}</h2>
                <p className="field-hint" style={{ marginTop: "0.25rem" }}>
                  {selectedPlaybookToTrigger.description}
                </p>
              </div>
              <button className="close-btn" onClick={() => setSelectedPlaybookToTrigger(null)}>✕</button>
            </header>

            {playbookActionMsg && <div className="alert alert-error">{playbookActionMsg}</div>}

            <form onSubmit={handleTriggerPlaybookSubmit} className="form-stack">
              <div className="form-group">
                <label>Target Incident (Optional)</label>
                <select
                  value={triggerIncidentId}
                  onChange={(e) => setTriggerIncidentId(e.target.value)}
                >
                  <option value="">No Incident Associated</option>
                  {incidents.map((inc) => (
                    <option key={inc.id} value={inc.id}>
                      [{inc.severity}] {inc.title}
                    </option>
                  ))}
                </select>
              </div>

              {selectedPlaybookToTrigger.actions.includes("REVOKE_USER_SESSIONS") && (
                <div className="form-group">
                  <label>Target User ID for Session Revocation</label>
                  <select
                    value={triggerParamUserId}
                    onChange={(e) => setTriggerParamUserId(e.target.value)}
                  >
                    <option value="">Select Target User</option>
                    {usersList.map((u) => (
                      <option key={u.id} value={u.id}>
                        {u.name} ({u.email}) - {u.role}
                      </option>
                    ))}
                  </select>
                  <p className="field-hint">
                    Anti-Privilege Escalation: Analysts cannot revoke sessions of Administrators or Super Admins.
                  </p>
                </div>
              )}

              {(selectedPlaybookToTrigger.actions.includes("ISOLATE_ENDPOINT") ||
                selectedPlaybookToTrigger.actions.includes("BLOCK_IP_FIREWALL")) && (
                <div className="form-group">
                  <label>Target Endpoint Hostname or IP Address</label>
                  <input
                    type="text"
                    placeholder="e.g. 198.51.100.25 or work-station-finance-01"
                    value={triggerParamTarget}
                    onChange={(e) => setTriggerParamTarget(e.target.value)}
                  />
                  <p className="field-hint">
                    Safety Protection: Loopback (127.0.0.1) and essential infrastructure IP ranges are shielded from isolation.
                  </p>
                </div>
              )}

              <div className="form-group">
                <label style={{ display: "flex", alignItems: "center", gap: "0.5rem", textTransform: "none", cursor: "pointer" }}>
                  <input
                    type="checkbox"
                    checked={triggerDryRun}
                    onChange={(e) => setTriggerDryRun(e.target.checked)}
                  />
                  <span>
                    <strong>Simulation Mode (Dry Run)</strong> — simulates actions safely without disrupting production systems.
                  </span>
                </label>
              </div>

              {selectedPlaybookToTrigger.requires_approval && (
                <div className="alert alert-info">
                  <strong>Dual Authorization Required:</strong> Because this playbook performs high-risk containment actions, an approval request will be submitted for peer administrator authorization before live execution.
                </div>
              )}

              <div className="modal-footer">
                <button type="button" className="secondary-btn" onClick={() => setSelectedPlaybookToTrigger(null)}>
                  Cancel
                </button>
                <button type="submit" className="primary-btn" disabled={playbookSubmitting}>
                  {playbookSubmitting ? "Executing..." : "Dispatch Playbook"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL 7: PLAYBOOK EXECUTION LOGS & DETAILS */}
      {selectedExecutionDetails && (
        <div className="modal-overlay" onClick={() => setSelectedExecutionDetails(null)}>
          <div className="modal-card" onClick={(e) => e.stopPropagation()} style={{ maxWidth: "700px" }}>
            <header className="modal-header">
              <div>
                <h2>Playbook Execution Log</h2>
                <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
                  ID: <code>{selectedExecutionDetails.id}</code> | Status: {selectedExecutionDetails.status}
                </span>
              </div>
              <button className="close-btn" onClick={() => setSelectedExecutionDetails(null)}>✕</button>
            </header>

            <div style={{ marginTop: "1rem" }}>
              <div className="meta-grid">
                <div>
                  <span className="meta-label">Mode</span>
                  <p><strong>{selectedExecutionDetails.is_dry_run ? "DRY RUN (Simulation)" : "LIVE"}</strong></p>
                </div>
                <div>
                  <span className="meta-label">Status</span>
                  <p>
                    <span className={`badge ${selectedExecutionDetails.status === "SUCCESS" ? "badge-success" : selectedExecutionDetails.status === "FAILED" ? "sev-critical" : "badge-inactive"}`}>
                      {selectedExecutionDetails.status}
                    </span>
                  </p>
                </div>
                <div>
                  <span className="meta-label">Trigger Source</span>
                  <p>
                    <span className="category-tag">
                      {selectedExecutionDetails.trigger_source || "MANUAL"}
                    </span>
                  </p>
                </div>
                <div>
                  <span className="meta-label">Target Incident</span>
                  <p style={{ fontSize: "0.8rem", fontFamily: "monospace" }}>
                    {selectedExecutionDetails.incident_id || "None"}
                  </p>
                </div>
                {selectedExecutionDetails.trigger_reason && (
                  <div style={{ gridColumn: "span 2" }}>
                    <span className="meta-label">Trigger Reason</span>
                    <p style={{ fontSize: "0.8rem", color: "var(--text-muted)", marginTop: "0.2rem" }}>
                      {selectedExecutionDetails.trigger_reason}
                    </p>
                  </div>
                )}
                <div>
                  <span className="meta-label">Started At</span>
                  <p>{selectedExecutionDetails.started_at ? new Date(selectedExecutionDetails.started_at).toLocaleString() : "—"}</p>
                </div>
                <div>
                  <span className="meta-label">Completed At</span>
                  <p>{selectedExecutionDetails.completed_at ? new Date(selectedExecutionDetails.completed_at).toLocaleString() : "—"}</p>
                </div>
              </div>

              <h4 style={{ marginTop: "1.25rem" }}>Step-by-Step Execution Trail</h4>
              <div className="execution-timeline">
                {(!selectedExecutionDetails.execution_log || selectedExecutionDetails.execution_log.length === 0) ? (
                  <p className="empty-message">No step logs recorded for this execution.</p>
                ) : (
                  selectedExecutionDetails.execution_log.map((step: any, idx: number) => (
                    <div key={idx} className="execution-step-row">
                      <span className="step-icon-status">
                        {step.status === "SUCCESS" ? "✅" : step.status === "SIMULATED" ? "🧪" : "❌"}
                      </span>
                      <div className="step-content">
                        <div className="step-title">
                          Action: <code>{step.action}</code> — {step.status}
                        </div>
                        <div className="step-meta">
                          {step.message || JSON.stringify(step.result || step.details || {})}
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>

            <div className="modal-footer" style={{ marginTop: "1.5rem" }}>
              <button type="button" className="secondary-btn" onClick={() => setSelectedExecutionDetails(null)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL 8: MFA ENROLLMENT */}
      {showEnrollModal && enrollData && (
        <div className="modal-overlay" onClick={() => setShowEnrollModal(false)}>
          <div className="modal-card" onClick={(e) => e.stopPropagation()} style={{ maxWidth: "600px" }}>
            <header className="modal-header">
              <h2>Setup Two-Factor Authentication</h2>
              <button className="close-btn" onClick={() => setShowEnrollModal(false)}>✕</button>
            </header>

            {enrollError && <div className="alert alert-error">{enrollError}</div>}

            <div style={{ textAlign: "center", margin: "1rem 0" }}>
              <p style={{ fontSize: "0.9rem", color: "var(--text-muted)", marginBottom: "1rem" }}>
                Scan the QR code with your authenticator app (Google Authenticator, Microsoft Authenticator, 1Password, or YubiKey).
              </p>
              <div style={{ display: "inline-block", background: "white", padding: "12px", borderRadius: "8px" }}>
                <img src={enrollData.qr_code} alt="TOTP QR Code" style={{ width: "192px", height: "192px", display: "block" }} />
              </div>
              <div style={{ marginTop: "1rem" }}>
                <span className="meta-label">Manual Entry Secret Key</span>
                <p style={{ fontFamily: "monospace", letterSpacing: "0.15rem", fontSize: "1.1rem", background: "var(--bg-card)", padding: "0.5rem", borderRadius: "4px", display: "inline-block" }}>
                  {enrollData.secret}
                </p>
              </div>
            </div>

            <div style={{ background: "rgba(148, 163, 184, 0.08)", padding: "1rem", borderRadius: "8px", margin: "1rem 0" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
                <strong>⚠️ Backup Recovery Codes (Save these!)</strong>
                <button
                  type="button"
                  className="secondary-btn btn-xs"
                  onClick={() => {
                    navigator.clipboard.writeText(enrollData.recovery_codes.join("\n"));
                    alert("Recovery codes copied to clipboard!");
                  }}
                >
                  📋 Copy Codes
                </button>
              </div>
              <p style={{ fontSize: "0.8rem", color: "var(--text-muted)", marginBottom: "0.75rem" }}>
                If you lose access to your device, each recovery code can be used once to access your account.
              </p>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.4rem", fontFamily: "monospace", fontSize: "0.85rem" }}>
                {enrollData.recovery_codes.map((rc, idx) => (
                  <div key={idx} style={{ background: "var(--bg-main)", padding: "0.3rem 0.5rem", borderRadius: "4px" }}>
                    {idx + 1}. {rc}
                  </div>
                ))}
              </div>
            </div>

            <form onSubmit={handleConfirmMfaEnrollment} className="form-stack">
              <div className="form-group">
                <label>Verification Code from Authenticator App *</label>
                <input
                  type="text"
                  required
                  autoFocus
                  placeholder="6-digit code (e.g. 123456)"
                  value={confirmTotpCode}
                  onChange={(e) => setConfirmTotpCode(e.target.value)}
                  maxLength={6}
                  style={{ textAlign: "center", fontSize: "1.25rem", letterSpacing: "0.2rem" }}
                />
              </div>

              <div className="modal-footer">
                <button type="button" className="secondary-btn" onClick={() => setShowEnrollModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="primary-btn" disabled={enrollSubmitting}>
                  {enrollSubmitting ? "Activating..." : "Verify & Activate MFA"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL 9: DISABLE MFA */}
      {showDisableMfaModal && (
        <div className="modal-overlay" onClick={() => setShowDisableMfaModal(false)}>
          <div className="modal-card" onClick={(e) => e.stopPropagation()} style={{ maxWidth: "450px" }}>
            <header className="modal-header">
              <h2>Disable Two-Factor Authentication</h2>
              <button className="close-btn" onClick={() => setShowDisableMfaModal(false)}>✕</button>
            </header>

            {disableError && <div className="alert alert-error">{disableError}</div>}

            <form onSubmit={handleDisableMfa} className="form-stack">
              <p style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>
                Disabling MFA reduces account security and removes Step-Up privileges for live playbook containment.
              </p>
              <div className="form-group">
                <label>Current Password *</label>
                <input
                  type="password"
                  required
                  placeholder="••••••••••••"
                  value={disablePassword}
                  onChange={(e) => setDisablePassword(e.target.value)}
                />
              </div>
              <div className="form-group">
                <label>Authenticator Code *</label>
                <input
                  type="text"
                  required
                  placeholder="6-digit TOTP code"
                  value={disableTotpCode}
                  onChange={(e) => setDisableTotpCode(e.target.value)}
                  maxLength={6}
                />
              </div>
              <div className="modal-footer">
                <button type="button" className="secondary-btn" onClick={() => setShowDisableMfaModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="primary-btn" style={{ background: "var(--accent-rose)", borderColor: "var(--accent-rose)" }} disabled={disableSubmitting}>
                  {disableSubmitting ? "Disabling..." : "Confirm & Disable MFA"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL 10: REGENERATE RECOVERY CODES */}
      {showRegenModal && (
        <div className="modal-overlay" onClick={() => setShowRegenModal(false)}>
          <div className="modal-card" onClick={(e) => e.stopPropagation()} style={{ maxWidth: "500px" }}>
            <header className="modal-header">
              <h2>Regenerate Recovery Codes</h2>
              <button className="close-btn" onClick={() => setShowRegenModal(false)}>✕</button>
            </header>

            {regenError && <div className="alert alert-error">{regenError}</div>}

            {regenCodes ? (
              <div>
                <div className="alert alert-success">
                  ✓ 10 new recovery codes generated! Previous recovery codes are now invalidated.
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.4rem", fontFamily: "monospace", margin: "1rem 0" }}>
                  {regenCodes.map((code, idx) => (
                    <div key={idx} style={{ background: "var(--bg-card)", padding: "0.35rem 0.5rem", borderRadius: "4px" }}>
                      {idx + 1}. {code}
                    </div>
                  ))}
                </div>
                <div className="modal-footer">
                  <button
                    type="button"
                    className="secondary-btn"
                    onClick={() => {
                      navigator.clipboard.writeText(regenCodes.join("\n"));
                      alert("Copied recovery codes to clipboard!");
                    }}
                  >
                    📋 Copy All
                  </button>
                  <button type="button" className="primary-btn" onClick={() => { setShowRegenModal(false); setRegenCodes(null); }}>
                    Done
                  </button>
                </div>
              </div>
            ) : (
              <form onSubmit={handleRegenerateCodes} className="form-stack">
                <p style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>
                  Generating new recovery codes will immediately invalidate all previously issued backup recovery codes.
                </p>
                <div className="form-group">
                  <label>Current Password *</label>
                  <input
                    type="password"
                    required
                    placeholder="••••••••••••"
                    value={regenPassword}
                    onChange={(e) => setRegenPassword(e.target.value)}
                  />
                </div>
                <div className="form-group">
                  <label>Authenticator Code *</label>
                  <input
                    type="text"
                    required
                    placeholder="6-digit TOTP code"
                    value={regenTotpCode}
                    onChange={(e) => setRegenTotpCode(e.target.value)}
                    maxLength={6}
                  />
                </div>
                <div className="modal-footer">
                  <button type="button" className="secondary-btn" onClick={() => setShowRegenModal(false)}>
                    Cancel
                  </button>
                  <button type="submit" className="primary-btn" disabled={regenSubmitting}>
                    {regenSubmitting ? "Generating..." : "Generate New Codes"}
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}

      {/* MODAL 11: PRIVILEGED ACTION STEP-UP PROMPT */}
      {showStepUpModal && (
        <div className="modal-overlay" onClick={() => setShowStepUpModal(false)}>
          <div className="modal-card" onClick={(e) => e.stopPropagation()} style={{ maxWidth: "450px" }}>
            <header className="modal-header">
              <h2>Privileged Action Authorization</h2>
              <button className="close-btn" onClick={() => setShowStepUpModal(false)}>✕</button>
            </header>

            {stepUpError && <div className="alert alert-error">{stepUpError}</div>}

            <form onSubmit={handleStepUpApproveSubmit} className="form-stack">
              <div style={{ textAlign: "center", marginBottom: "1rem" }}>
                <span style={{ fontSize: "2rem" }}>🛡️</span>
                <h3 style={{ marginTop: "0.25rem", color: "var(--accent-amber)" }}>Step-Up Verification Required</h3>
                <p style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>
                  Live response playbook actions can disrupt host networks and user sessions. Enter your authenticator security code to authorize execution.
                </p>
              </div>

              <div className="form-group">
                <label>Authenticator Security Code *</label>
                <input
                  type="text"
                  required
                  autoFocus
                  placeholder="123456"
                  value={stepUpCode}
                  onChange={(e) => setStepUpCode(e.target.value)}
                  maxLength={6}
                  style={{ textAlign: "center", fontSize: "1.25rem", letterSpacing: "0.2rem" }}
                />
              </div>

              <div className="modal-footer">
                <button type="button" className="secondary-btn" onClick={() => setShowStepUpModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="primary-btn" disabled={stepUpSubmitting}>
                  {stepUpSubmitting ? "Authorizing..." : "Authorize Live Action"}
                </button>
              </div>
            </form>
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
