import { useEffect, useRef, useState } from "react";
import "./App.css";

const BACKEND_URL = "http://127.0.0.1:3000";

const DEFAULT_ANALYSIS = {
  analyzedUrl: "No website analyzed",
  riskLevel: "safe",
  score: 0,
  reasons: ["Analyze a website to begin a security check."],
  source: "default",
};

const RISK_META = {
  safe: {
    label: "Safe",
    color: "#22c55e",
    description:
      "No obvious URL-based threats were detected.",
  },
  suspicious: {
    label: "Suspicious",
    color: "#f59e0b",
    description:
      "This website contains characteristics that require caution.",
  },
  dangerous: {
    label: "Dangerous",
    color: "#ef4444",
    description:
      "This website has multiple potentially dangerous characteristics.",
  },
};

function App() {
  const [activeSection, setActiveSection] =
    useState("dashboard");

  const [url, setUrl] = useState("");

  const [analysis, setAnalysis] =
    useState(DEFAULT_ANALYSIS);

  const [history, setHistory] = useState([]);

  const [stats, setStats] = useState({
    scanned: 0,
    threats: 0,
    protected: 0,
  });

  const [backendStatus, setBackendStatus] =
    useState("checking");

  const [loading, setLoading] =
    useState(false);

  const [savingOverride, setSavingOverride] =
    useState(false);

  const [message, setMessage] =
    useState("");

  const [messageType, setMessageType] =
    useState("info");

  const analysisInProgress =
    useRef(false);

  const messageTimer =
    useRef(null);

  useEffect(() => {
    const savedAnalysis =
      localStorage.getItem(
        "securesense-current-analysis"
      );

    if (savedAnalysis) {
      try {
        setAnalysis(
          JSON.parse(savedAnalysis)
        );
      } catch {
        localStorage.removeItem(
          "securesense-current-analysis"
        );
      }
    }

    loadDashboardData();

    return () => {
      if (messageTimer.current) {
        clearTimeout(
          messageTimer.current
        );
      }
    };
  }, []);

  function showMessage(
    text,
    type = "info"
  ) {
    setMessage(text);
    setMessageType(type);

    if (messageTimer.current) {
      clearTimeout(
        messageTimer.current
      );
    }

    messageTimer.current =
      setTimeout(() => {
        setMessage("");
      }, 4500);
  }

  async function getResponseError(
    response,
    fallback
  ) {
    try {
      const data =
        await response.json();

      if (data?.error) {
        return data.error;
      }

      return fallback;
    } catch {
      return fallback;
    }
  }

  async function checkBackendHealth() {
    try {
      const response =
        await fetch(
          `${BACKEND_URL}/api/health`
        );

      if (!response.ok) {
        throw new Error(
          "Backend health check failed"
        );
      }

      setBackendStatus("online");

      return true;
    } catch {
      setBackendStatus("offline");

      return false;
    }
  }

  async function loadHistory() {
    try {
      const response =
        await fetch(
          `${BACKEND_URL}/api/history`
        );

      if (!response.ok) {
        throw new Error(
          "Could not load scan history"
        );
      }

      const data =
        await response.json();

      setHistory(
        Array.isArray(data)
          ? data
          : []
      );

      setBackendStatus("online");

      return true;
    } catch {
      setBackendStatus("offline");

      setHistory([]);

      return false;
    }
  }

  async function loadStats() {
    try {
      const response =
        await fetch(
          `${BACKEND_URL}/api/stats`
        );

      if (!response.ok) {
        throw new Error(
          "Could not load statistics"
        );
      }

      const data =
        await response.json();

      setStats({
        scanned:
          Number(data.scanned) || 0,
        threats:
          Number(data.threats) || 0,
        protected:
          Number(data.protected) || 0,
      });

      setBackendStatus("online");

      return true;
    } catch {
      setBackendStatus("offline");

      return false;
    }
  }

  async function loadDashboardData() {
    await Promise.all([
      checkBackendHealth(),
      loadHistory(),
      loadStats(),
    ]);
  }

  function normalizeInputUrl(value) {
    const trimmed =
      value.trim();

    if (!trimmed) {
      throw new Error(
        "Please enter a website URL."
      );
    }

    const withProtocol =
      /^https?:\/\//i.test(
        trimmed
      )
        ? trimmed
        : `https://${trimmed}`;

    let parsed;

    try {
      parsed =
        new URL(withProtocol);
    } catch {
      throw new Error(
        "Please enter a valid website URL."
      );
    }

    if (
      !["http:", "https:"].includes(
        parsed.protocol
      )
    ) {
      throw new Error(
        "Only HTTP and HTTPS websites are supported."
      );
    }

    if (!parsed.hostname) {
      throw new Error(
        "The URL must contain a valid website hostname."
      );
    }

    return parsed.href;
  }

  async function saveScanToHistory(
    result,
    scannedUrl
  ) {
    try {
      const response =
        await fetch(
          `${BACKEND_URL}/api/history`,
          {
            method: "POST",
            headers: {
              "Content-Type":
                "application/json",
            },
            body: JSON.stringify({
              url: scannedUrl,
              analyzedUrl:
                result.url ||
                result.analyzedUrl ||
                scannedUrl,
              status:
                result.riskLevel,
              score:
                result.score,
              reasons:
                result.reasons,
              scannedAt:
                new Date().toISOString(),
            }),
          }
        );

      if (!response.ok) {
        const error =
          await getResponseError(
            response,
            "Could not save scan history."
          );

        throw new Error(error);
      }

      setBackendStatus("online");

      return true;
    } catch (error) {
      setBackendStatus("offline");

      showMessage(
        error.message ||
          "Could not save scan history.",
        "error"
      );

      return false;
    }
  }

  async function analyzeWebsite() {
    if (
      analysisInProgress.current
    ) {
      return;
    }

    let cleanUrl;

    try {
      cleanUrl =
        normalizeInputUrl(url);
    } catch (error) {
      showMessage(
        error.message,
        "error"
      );

      return;
    }

    analysisInProgress.current =
      true;

    setLoading(true);
    setMessage("");

    try {
      const response =
        await fetch(
          `${BACKEND_URL}/api/analyze`,
          {
            method: "POST",
            headers: {
              "Content-Type":
                "application/json",
            },
            body: JSON.stringify({
              url: cleanUrl,
            }),
          }
        );

      if (!response.ok) {
        const error =
          await getResponseError(
            response,
            "Website analysis failed."
          );

        throw new Error(error);
      }

      const result =
        await response.json();

      const normalizedResult = {
        analyzedUrl:
          result.url ||
          cleanUrl,

        riskLevel:
          result.riskLevel ||
          "safe",

        score:
          Number(result.score) || 0,

        reasons:
          Array.isArray(
            result.reasons
          )
            ? result.reasons
            : [
                "No additional information was provided.",
              ],

        source:
          result.source ||
          "url-analysis",
      };

      setAnalysis(
        normalizedResult
      );

      localStorage.setItem(
        "securesense-current-analysis",
        JSON.stringify(
          normalizedResult
        )
      );

      setUrl(cleanUrl);

      setBackendStatus("online");

      await saveScanToHistory(
        normalizedResult,
        cleanUrl
      );

      await Promise.all([
        loadHistory(),
        loadStats(),
      ]);

      const risk =
        normalizedResult.riskLevel;

      showMessage(
        `${
          RISK_META[risk]?.label ||
          "Website"
        } analysis completed.`,
        risk === "dangerous"
          ? "error"
          : risk === "suspicious"
          ? "warning"
          : "success"
      );

      setActiveSection(
        "scanner"
      );
    } catch (error) {
      setBackendStatus(
        "offline"
      );

      showMessage(
        error.message ||
          "Unable to connect to the SecureSense backend. Make sure the server is running.",
        "error"
      );
    } finally {
      setLoading(false);

      analysisInProgress.current =
        false;
    }
  }

  async function saveManualOverride(
    status
  ) {
    if (savingOverride) {
      return;
    }

    let cleanUrl;

    try {
      cleanUrl =
        normalizeInputUrl(url);
    } catch (error) {
      showMessage(
        error.message,
        "error"
      );

      return;
    }

    setSavingOverride(true);

    try {
      const response =
        await fetch(
          `${BACKEND_URL}/api/overrides`,
          {
            method: "POST",
            headers: {
              "Content-Type":
                "application/json",
            },
            body: JSON.stringify({
              url: cleanUrl,
              status,
            }),
          }
        );

      if (!response.ok) {
        const error =
          await getResponseError(
            response,
            "Could not save the website override."
          );

        throw new Error(error);
      }

      const scoreMap = {
        trusted: 0,
        suspicious: 60,
        dangerous: 90,
      };

      const riskMap = {
        trusted: "safe",
        suspicious: "suspicious",
        dangerous: "dangerous",
      };

      const overrideResult = {
        analyzedUrl: cleanUrl,
        riskLevel:
          riskMap[status],
        score:
          scoreMap[status],
        reasons: [
          `Website has a saved user override: ${status}`,
        ],
        source: "override",
      };

      setAnalysis(
        overrideResult
      );

      localStorage.setItem(
        "securesense-current-analysis",
        JSON.stringify(
          overrideResult
        )
      );

      setBackendStatus("online");

      await saveScanToHistory(
        overrideResult,
        cleanUrl
      );

      await Promise.all([
        loadHistory(),
        loadStats(),
      ]);

      showMessage(
        `Website marked as ${status}.`,
        status === "dangerous"
          ? "error"
          : status === "suspicious"
          ? "warning"
          : "success"
      );
    } catch (error) {
      setBackendStatus(
        "offline"
      );

      showMessage(
        error.message ||
          "Could not save website override.",
        "error"
      );
    } finally {
      setSavingOverride(
        false
      );
    }
  }

  async function clearScanHistory() {
    const confirmed =
      window.confirm(
        "Clear all SecureSense scan history and reset dashboard statistics?"
      );

    if (!confirmed) {
      return;
    }

    try {
      const response =
        await fetch(
          `${BACKEND_URL}/api/history`,
          {
            method: "DELETE",
          }
        );

      if (!response.ok) {
        const error =
          await getResponseError(
            response,
            "Could not clear scan history."
          );

        throw new Error(error);
      }

      setHistory([]);

      setStats({
        scanned: 0,
        threats: 0,
        protected: 0,
      });

      setBackendStatus("online");

      showMessage(
        "Scan history and dashboard statistics were cleared.",
        "success"
      );
    } catch (error) {
      setBackendStatus(
        "offline"
      );

      showMessage(
        error.message ||
          "Could not clear scan history.",
        "error"
      );
    }
  }

  async function refreshDashboard() {
    showMessage(
      "Refreshing dashboard data...",
      "info"
    );

    await loadDashboardData();

    showMessage(
      "Dashboard data refreshed.",
      "success"
    );
  }

  function restoreScan(scan) {
    const restoredUrl =
      scan.analyzedUrl ||
      scan.url ||
      "";

    setUrl(restoredUrl);

    const restoredAnalysis = {
      analyzedUrl:
        restoredUrl,

      riskLevel:
        scan.status ||
        "safe",

      score:
        Number(scan.score) ||
        0,

      reasons:
        Array.isArray(
          scan.reasons
        ) &&
        scan.reasons.length
          ? scan.reasons
          : [
              "No reasons were stored for this scan.",
            ],

      source: "history",
    };

    setAnalysis(
      restoredAnalysis
    );

    localStorage.setItem(
      "securesense-current-analysis",
      JSON.stringify(
        restoredAnalysis
      )
    );

    setActiveSection(
      "scanner"
    );

    showMessage(
      "Previous scan restored.",
      "success"
    );
  }

  function scrollToSection(
    section
  ) {
    setActiveSection(section);

    const element =
      document.getElementById(
        section
      );

    if (element) {
      element.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    }
  }

  function formatDate(
    dateString
  ) {
    if (!dateString) {
      return "Unknown time";
    }

    const date =
      new Date(dateString);

    if (
      Number.isNaN(
        date.getTime()
      )
    ) {
      return "Unknown time";
    }

    return date.toLocaleString();
  }

  function getRiskMeta(level) {
    return (
      RISK_META[level] ||
      RISK_META.safe
    );
  }

  const riskMeta =
    getRiskMeta(
      analysis.riskLevel
    );

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <div className="brand-icon">
            S
          </div>

          <div>
            <div className="brand-name">
              SecureSense
            </div>

            <div className="brand-subtitle">
              Web Security
            </div>
          </div>
        </div>

        <div className="backend-pill">
          <span
            className={`status-dot ${backendStatus}`}
          />

          {backendStatus ===
            "online" &&
            "Backend Online"}

          {backendStatus ===
            "offline" &&
            "Backend Offline"}

          {backendStatus ===
            "checking" &&
            "Checking Backend"}
        </div>
      </header>

      <div className="layout">
        <aside className="sidebar">
          <div className="sidebar-brand">
            <div className="shield-icon">
              ♡
            </div>

            <div>
              <div className="sidebar-title">
                SecureSense
              </div>

              <div className="sidebar-subtitle">
                Web Security
              </div>
            </div>
          </div>

          <div className="nav-label">
            WORKSPACE
          </div>

          <button
            className={`nav-item ${
              activeSection ===
              "dashboard"
                ? "active"
                : ""
            }`}
            onClick={() =>
              scrollToSection(
                "dashboard"
              )
            }
          >
            <span>🏠</span>
            Dashboard
          </button>

          <button
            className={`nav-item ${
              activeSection ===
              "scanner"
                ? "active"
                : ""
            }`}
            onClick={() =>
              scrollToSection(
                "scanner"
              )
            }
          >
            <span>🔍</span>
            Website Scanner
          </button>

          <button
            className={`nav-item ${
              activeSection ===
              "history"
                ? "active"
                : ""
            }`}
            onClick={() =>
              scrollToSection(
                "history"
              )
            }
          >
            <span>📋</span>
            Scan History
          </button>

          <button
            className={`nav-item ${
              activeSection ===
              "settings"
                ? "active"
                : ""
            }`}
            onClick={() =>
              scrollToSection(
                "settings"
              )
            }
          >
            <span>⚙️</span>
            Settings
          </button>

          <div className="system-status">
            <div
              className={`system-status-title ${
                backendStatus ===
                "online"
                  ? "online"
                  : ""
              }`}
            >
              ●{" "}
              {backendStatus ===
              "online"
                ? "System Active"
                : backendStatus ===
                  "offline"
                ? "System Offline"
                : "Checking System"}
            </div>

            <div className="system-status-text">
              {backendStatus ===
              "online"
                ? "Protection is running"
                : "Backend connection required"}
            </div>
          </div>
        </aside>

        <main className="main">
          <section
            id="dashboard"
            className="section"
          >
            <div className="hero">
              <div>
                <p className="eyebrow">
                  SECURITY DASHBOARD
                </p>

                <h1>
                  Browse with confidence.
                </h1>

                <p>
                  SecureSense analyzes
                  website URLs for
                  potentially risky
                  characteristics and
                  keeps a persistent
                  record of your scans.
                </p>
              </div>

              <button
                className="secondary-button"
                onClick={
                  refreshDashboard
                }
              >
                Refresh Data
              </button>
            </div>

            <div className="stats-grid">
              <div className="stat-card">
                <div className="stat-title">
                  Websites Scanned
                </div>

                <div className="stat-value">
                  {stats.scanned}
                </div>

                <div className="stat-description">
                  ↑ Latest unique websites
                </div>
              </div>

              <div className="stat-card">
                <div className="stat-title">
                  Threats Detected
                </div>

                <div className="stat-value">
                  {stats.threats}
                </div>

                <div className="stat-description">
                  Requires attention
                </div>
              </div>

              <div className="stat-card">
                <div className="stat-title">
                  Protected Websites
                </div>

                <div className="stat-value">
                  {stats.protected}
                </div>

                <div className="stat-description">
                  Latest safe results
                </div>
              </div>
            </div>
          </section>

          <section
            id="scanner"
            className="section"
          >
            <div className="scanner-panel">
              <div className="scanner-header">
                <div>
                  <div className="section-label">
                    WEBSITE SCANNER
                  </div>

                  <h2>
                    Analyze a Website
                  </h2>

                  <p>
                    Enter a URL to check
                    for potentially risky
                    characteristics.
                  </p>
                </div>

                <span
                  className={`risk-badge ${analysis.riskLevel}`}
                >
                  ●{" "}
                  {riskMeta.label.toUpperCase()}
                </span>
              </div>

              <div className="scanner-input-row">
                <input
                  className="url-input"
                  type="text"
                  value={url}
                  placeholder="example.com or https://example.com/login"
                  onChange={(event) =>
                    setUrl(
                      event.target
                        .value
                    )
                  }
                  onKeyDown={(
                    event
                  ) => {
                    if (
                      event.key ===
                        "Enter" &&
                      !loading
                    ) {
                      analyzeWebsite();
                    }
                  }}
                />

                <button
                  className="analyze-button"
                  onClick={
                    analyzeWebsite
                  }
                  disabled={
                    loading ||
                    backendStatus ===
                      "offline"
                  }
                >
                  {loading
                    ? "Analyzing..."
                    : "Analyze Website"}
                </button>
              </div>

              {message && (
                <div
                  className={`message ${messageType}`}
                >
                  {message}
                </div>
              )}
            </div>

            <div className="analysis-layout">
              <div className="analysis-card">
                <div className="analysis-top">
                  <div>
                    <div className="section-label">
                      CURRENT ANALYSIS
                    </div>

                    <h2 className="analysis-url-title">
                      {analysis.analyzedUrl
                        ? analysis.analyzedUrl
                            .replace(
                              /^https?:\/\//i,
                              ""
                            )
                            .split(
                              "/"
                            )[0]
                        : "example.com"}
                    </h2>
                  </div>

                  <span
                    className={`risk-badge ${analysis.riskLevel}`}
                  >
                    ●{" "}
                    {riskMeta.label.toUpperCase()}
                  </span>
                </div>

                <div className="analysis-main">
                  <div
                    className="risk-circle"
                    style={{
                      "--risk-color":
                        riskMeta.color,
                    }}
                  >
                    <div className="risk-score">
                      {analysis.score}
                    </div>

                    <div className="risk-label">
                      RISK SCORE
                    </div>
                  </div>

                  <div className="assessment">
                    <h2>
                      Security assessment
                    </h2>

                    <p>
                      {riskMeta.description}
                    </p>
                  </div>
                </div>

                <div className="detection-section">
                  <div className="section-label centered">
                    DETECTION REASONS
                  </div>

                  <div className="reasons">
                    {analysis.reasons.map(
                      (
                        reason,
                        index
                      ) => (
                        <div
                          className="reason"
                          key={`${reason}-${index}`}
                        >
                          <span>
                            ✓
                          </span>

                          <div>
                            {reason}
                          </div>
                        </div>
                      )
                    )}
                  </div>
                </div>

                <div className="analysis-url">
                  <strong>
                    Analyzed URL:
                  </strong>{" "}
                  {analysis.analyzedUrl}
                </div>

                <div className="analysis-note">
                  SecureSense currently
                  performs heuristic
                  URL-based analysis.
                  A safe result does not
                  guarantee that a website
                  is completely free from
                  malware, phishing, or
                  other threats.
                </div>
              </div>

              <div className="control-card">
                <div className="section-label centered">
                  MANUAL CONTROL
                </div>

                <h2>
                  Change Website Status
                </h2>

                <p>
                  If SecureSense
                  incorrectly classifies a
                  website, you can manually
                  change its status.
                </p>

                <div className="override-grid">
                  <button
                    className="override-button trusted"
                    disabled={
                      savingOverride ||
                      backendStatus ===
                        "offline"
                    }
                    onClick={() =>
                      saveManualOverride(
                        "trusted"
                      )
                    }
                  >
                    ✓ Mark as Trusted
                  </button>

                  <button
                    className="override-button suspicious"
                    disabled={
                      savingOverride ||
                      backendStatus ===
                        "offline"
                    }
                    onClick={() =>
                      saveManualOverride(
                        "suspicious"
                      )
                    }
                  >
                    ⚠ Mark as Suspicious
                  </button>

                  <button
                    className="override-button dangerous"
                    disabled={
                      savingOverride ||
                      backendStatus ===
                        "offline"
                    }
                    onClick={() =>
                      saveManualOverride(
                        "dangerous"
                      )
                    }
                  >
                    ⚠ Mark as Dangerous
                  </button>
                </div>

                <div className="control-note">
                  Your manual decision is
                  saved by the SecureSense
                  backend and remains after
                  refreshing the page.
                </div>
              </div>
            </div>
          </section>

          <section
            id="history"
            className="section"
          >
            <div className="content-panel">
              <div className="panel-header">
                <div>
                  <div className="section-label">
                    SCAN HISTORY
                  </div>

                  <h2>
                    Recent Scans
                  </h2>
                </div>

                <button
                  className="danger-button"
                  onClick={
                    clearScanHistory
                  }
                  disabled={
                    history.length ===
                      0 ||
                    backendStatus ===
                      "offline"
                  }
                >
                  Clear History
                </button>
              </div>

              {history.length ===
              0 ? (
                <div className="empty-state">
                  No scan history yet.
                  Analyze a website to
                  start building your
                  security history.
                </div>
              ) : (
                <div className="history-list">
                  {history.map(
                    (scan) => {
                      const scanStatus =
                        scan.status ||
                        "safe";

                      return (
                        <div
                          className="history-item"
                          key={
                            scan.id
                          }
                        >
                          <div className="history-main">
                            <div className="history-url">
                              {scan.analyzedUrl ||
                                scan.url ||
                                "Unknown URL"}
                            </div>

                            <div className="history-meta">
                              Score{" "}
                              {Number(
                                scan.score
                              ) || 0}
                              {" · "}
                              {formatDate(
                                scan.scannedAt
                              )}
                            </div>
                          </div>

                          <div className="history-right">
                            <span
                              className={`risk-badge ${scanStatus}`}
                            >
                              {getRiskMeta(
                                scanStatus
                              ).label.toUpperCase()}
                            </span>

                            <button
                              className="restore-button"
                              onClick={() =>
                                restoreScan(
                                  scan
                                )
                              }
                            >
                              Restore
                            </button>
                          </div>
                        </div>
                      );
                    }
                  )}
                </div>
              )}
            </div>
          </section>

          <section
            id="settings"
            className="section"
          >
            <div className="content-panel">
              <div className="panel-header">
                <div>
                  <div className="section-label">
                    SETTINGS
                  </div>

                  <h2>
                    SecureSense Settings
                  </h2>
                </div>
              </div>

              <div className="settings-grid">
                <div className="settings-card">
                  <h3>
                    Backend Connection
                  </h3>

                  <div className="settings-row">
                    <div>
                      <div className="settings-name">
                        Server Status
                      </div>

                      <div className="settings-value">
                        {backendStatus ===
                          "online" &&
                          "SecureSense backend is reachable."}

                        {backendStatus ===
                          "offline" &&
                          "Backend cannot currently be reached."}

                        {backendStatus ===
                          "checking" &&
                          "Checking backend connection..."}
                      </div>
                    </div>

                    <span
                      className={`status-dot ${backendStatus}`}
                    />
                  </div>

                  <div className="settings-row">
                    <div>
                      <div className="settings-name">
                        Backend URL
                      </div>

                      <div className="settings-value">
                        {BACKEND_URL}
                      </div>
                    </div>
                  </div>

                  <button
                    className="secondary-button"
                    onClick={
                      checkBackendHealth
                    }
                  >
                    Check Connection
                  </button>
                </div>

                <div className="settings-card">
                  <h3>
                    Dashboard Data
                  </h3>

                  <div className="settings-row">
                    <div>
                      <div className="settings-name">
                        Stored Scans
                      </div>

                      <div className="settings-value">
                        {history.length}{" "}
                        scan
                        {history.length ===
                        1
                          ? ""
                          : "s"}{" "}
                        currently stored.
                      </div>
                    </div>
                  </div>

                  <div className="settings-row">
                    <div>
                      <div className="settings-name">
                        History Limit
                      </div>

                      <div className="settings-value">
                        Backend stores the
                        latest 50 scans.
                      </div>
                    </div>
                  </div>

                  <button
                    className="danger-button"
                    onClick={
                      clearScanHistory
                    }
                    disabled={
                      history.length ===
                        0 ||
                      backendStatus ===
                        "offline"
                    }
                  >
                    Clear All Scan Data
                  </button>
                </div>
              </div>
            </div>
          </section>
        </main>
      </div>

      <style>{`
        * {
          box-sizing: border-box;
        }

        html {
          scroll-behavior: smooth;
        }

        body {
          margin: 0;
          background: #090f1d;
          color: #f8fafc;
          font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        }

        button,
        input {
          font: inherit;
        }

        button {
          cursor: pointer;
        }

        .app {
          min-height: 100vh;
          background: #090f1d;
          color: #f8fafc;
        }

        .topbar {
          position: sticky;
          top: 0;
          z-index: 20;
          height: 86px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 0 36px;
          background: #0d1424;
          border-bottom: 1px solid #1d293d;
        }

        .brand {
          display: flex;
          align-items: center;
          gap: 13px;
        }

        .brand-icon {
          width: 43px;
          height: 43px;
          display: grid;
          place-items: center;
          border-radius: 11px;
          background: linear-gradient(135deg, #5865f2, #7c5cff);
          color: white;
          font-size: 24px;
          font-weight: 900;
          box-shadow: 0 8px 25px rgba(88, 101, 242, .25);
        }

        .brand-name {
          font-size: 22px;
          font-weight: 850;
        }

        .brand-subtitle {
          margin-top: 2px;
          color: #7f91b0;
          font-size: 12px;
        }

        .backend-pill {
          display: flex;
          align-items: center;
          gap: 9px;
          padding: 10px 15px;
          border: 1px solid #243149;
          border-radius: 999px;
          background: #10192a;
          color: #9fb0cc;
          font-size: 13px;
          font-weight: 700;
        }

        .status-dot {
          width: 9px;
          height: 9px;
          display: inline-block;
          border-radius: 50%;
          background: #64748b;
        }

        .status-dot.online {
          background: #22c55e;
          box-shadow: 0 0 0 4px rgba(34, 197, 94, .12);
        }

        .status-dot.offline {
          background: #ef4444;
          box-shadow: 0 0 0 4px rgba(239, 68, 68, .12);
        }

        .status-dot.checking {
          background: #f59e0b;
          box-shadow: 0 0 0 4px rgba(245, 158, 11, .12);
        }

        .layout {
          display: flex;
          min-height: calc(100vh - 86px);
        }

        .sidebar {
          position: sticky;
          top: 86px;
          width: 276px;
          height: calc(100vh - 86px);
          padding: 40px 22px 25px;
          background: #101827;
          border-right: 1px solid #1d293d;
        }

        .sidebar-brand {
          display: flex;
          align-items: center;
          gap: 12px;
          margin-bottom: 55px;
          padding-left: 1px;
        }

        .shield-icon {
          width: 48px;
          height: 48px;
          display: grid;
          place-items: center;
          border-radius: 11px;
          background: linear-gradient(135deg, #5865f2, #7c5cff);
          color: white;
          font-size: 22px;
        }

        .sidebar-title {
          font-size: 23px;
          font-weight: 850;
        }

        .sidebar-subtitle {
          margin-top: 5px;
          color: #8ca0c0;
          font-size: 13px;
          text-align: center;
        }

        .nav-label,
        .section-label {
          color: #6980a3;
          font-size: 12px;
          font-weight: 800;
          letter-spacing: .08em;
        }

        .nav-label {
          margin: 0 0 13px 10px;
        }

        .nav-item {
          width: 100%;
          display: flex;
          align-items: center;
          gap: 15px;
          margin-bottom: 7px;
          padding: 14px 17px;
          border: 0;
          border-radius: 11px;
          background: transparent;
          color: #8ea2c3;
          font-size: 17px;
          font-weight: 650;
          text-align: left;
        }

        .nav-item span {
          width: 22px;
          text-align: center;
        }

        .nav-item:hover {
          background: #172338;
          color: #dce6f7;
        }

        .nav-item.active {
          background: #1d2a40;
          color: #8fa8ff;
        }

        .system-status {
          position: absolute;
          left: 22px;
          right: 22px;
          bottom: 28px;
          padding: 20px;
          border: 1px solid #25344c;
          border-radius: 12px;
          background: #0f1829;
          text-align: center;
        }

        .system-status-title {
          color: #ef4444;
          font-size: 13px;
          font-weight: 750;
        }

        .system-status-title.online {
          color: #22c55e;
        }

        .system-status-text {
          margin-top: 17px;
          color: #8da0bf;
          font-size: 13px;
        }

        .main {
          flex: 1;
          min-width: 0;
          padding: 50px 54px;
          background: #090f1d;
        }

        .section {
          scroll-margin-top: 105px;
          margin-bottom: 35px;
        }

        .hero {
          display: flex;
          align-items: flex-end;
          justify-content: space-between;
          gap: 25px;
          margin-bottom: 28px;
        }

        .eyebrow {
          margin: 0 0 9px;
          color: #7589aa;
          font-size: 13px;
          font-weight: 850;
          letter-spacing: .1em;
        }

        h1 {
          margin: 0;
          color: #f8fafc;
          font-size: 38px;
          line-height: 1.12;
          letter-spacing: -.035em;
        }

        .hero p {
          max-width: 720px;
          margin: 13px 0 0;
          color: #8ea1c1;
          font-size: 16px;
          line-height: 1.65;
        }

        .stats-grid {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 20px;
        }

        .stat-card {
          min-height: 150px;
          padding: 28px 24px;
          border: 1px solid #202d42;
          border-radius: 15px;
          background: #101827;
          text-align: center;
        }

        .stat-title {
          color: #6f84a7;
          font-size: 15px;
        }

        .stat-value {
          margin-top: 12px;
          color: #f8fafc;
          font-size: 39px;
          font-weight: 850;
        }

        .stat-description {
          margin-top: 5px;
          color: #22c55e;
          font-size: 13px;
        }

        .secondary-button,
        .danger-button,
        .restore-button {
          border: 1px solid #27364e;
          border-radius: 10px;
          background: #121c2d;
          color: #d4deed;
          padding: 12px 17px;
          font-weight: 750;
        }

        .secondary-button:hover,
        .restore-button:hover {
          background: #18253a;
        }

        .danger-button {
          border-color: #64252a;
          background: #29151b;
          color: #f87171;
        }

        .danger-button:hover {
          background: #3a171d;
        }

        .scanner-panel,
        .analysis-card,
        .control-card,
        .content-panel {
          border: 1px solid #202d42;
          border-radius: 16px;
          background: #101827;
          box-shadow: 0 14px 35px rgba(0, 0, 0, .12);
        }

        .scanner-panel {
          padding: 27px 30px;
          margin-top: 25px;
        }

        .scanner-header,
        .panel-header,
        .analysis-top {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 20px;
        }

        .scanner-header h2,
        .panel-header h2 {
          margin: 8px 0 0;
          color: #f8fafc;
          font-size: 23px;
        }

        .scanner-header p {
          margin: 7px 0 0;
          color: #7f94b5;
        }

        .scanner-input-row {
          display: flex;
          gap: 12px;
          margin-top: 24px;
        }

        .url-input {
          flex: 1;
          min-width: 0;
          padding: 15px 18px;
          border: 1px solid #30405a;
          border-radius: 11px;
          outline: none;
          background: #0b1322;
          color: #e8eef8;
          font-size: 16px;
        }

        .url-input::placeholder {
          color: #647894;
        }

        .url-input:focus {
          border-color: #596bff;
          box-shadow: 0 0 0 3px rgba(89, 107, 255, .13);
        }

        .analyze-button {
          padding: 14px 23px;
          border: 0;
          border-radius: 11px;
          background: #315fe8;
          color: white;
          font-weight: 800;
          box-shadow: 0 8px 20px rgba(49, 95, 232, .2);
        }

        .analyze-button:hover {
          background: #3b6cf4;
        }

        button:disabled {
          cursor: not-allowed;
          opacity: .5;
        }

        .message {
          margin-top: 14px;
          padding: 12px 15px;
          border-radius: 9px;
          font-size: 13px;
          font-weight: 700;
        }

        .message.info {
          background: #13233e;
          color: #8fb2ff;
        }

        .message.success {
          background: #0b2a1b;
          color: #4ade80;
        }

        .message.warning {
          background: #321e09;
          color: #fbbf24;
        }

        .message.error {
          background: #351418;
          color: #f87171;
        }

        .analysis-layout {
          display: grid;
          grid-template-columns: minmax(0, 1.65fr) minmax(300px, .9fr);
          gap: 24px;
          margin-top: 25px;
        }

        .analysis-card,
        .control-card {
          padding: 29px;
        }

        .analysis-url-title {
          margin: 10px 0 0;
          color: #f8fafc;
          font-size: 23px;
        }

        .risk-badge {
          display: inline-flex;
          align-items: center;
          gap: 5px;
          padding: 10px 15px;
          border-radius: 999px;
          font-size: 12px;
          font-weight: 850;
        }

        .risk-badge.safe {
          background: #06391e;
          color: #22c55e;
        }

        .risk-badge.suspicious {
          background: #452507;
          color: #f59e0b;
        }

        .risk-badge.dangerous {
          background: #480e13;
          color: #ef4444;
        }

        .analysis-main {
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 38px;
          min-height: 220px;
        }

        .risk-circle {
          width: 168px;
          height: 168px;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          flex-shrink: 0;
          border: 10px solid var(--risk-color);
          border-radius: 50%;
          color: #f8fafc;
          background: #111a2b;
        }

        .risk-score {
          font-size: 42px;
          font-weight: 900;
        }

        .risk-label {
          margin-top: -2px;
          color: #6f84a5;
          font-size: 12px;
        }

        .assessment {
          max-width: 390px;
          text-align: center;
        }

        .assessment h2 {
          color: #f8fafc;
          font-size: 23px;
        }

        .assessment p {
          color: #8fa3c1;
          line-height: 1.6;
        }

        .detection-section {
          padding-top: 24px;
          border-top: 1px solid #1f2b40;
        }

        .centered {
          text-align: center;
        }

        .reasons {
          margin-top: 18px;
        }

        .reason {
          display: flex;
          gap: 12px;
          padding: 17px 18px;
          margin-bottom: 8px;
          border-radius: 7px;
          background: #0c1525;
          color: #d9e2f0;
          font-size: 14px;
        }

        .reason span {
          color: #67e8a0;
          font-weight: 900;
        }

        .analysis-url {
          margin-top: 18px;
          padding: 12px 15px;
          border: 1px solid #202e44;
          border-radius: 8px;
          background: #0b1423;
          color: #91a5c4;
          font-size: 12px;
          word-break: break-all;
        }

        .analysis-note {
          margin-top: 18px;
          color: #617594;
          font-size: 11px;
          line-height: 1.6;
        }

        .control-card {
          text-align: center;
        }

        .control-card h2 {
          margin: 22px 0 10px;
          color: #f8fafc;
          font-size: 25px;
        }

        .control-card > p {
          color: #8196b6;
          line-height: 1.6;
        }

        .override-grid {
          display: grid;
          gap: 11px;
          margin-top: 28px;
        }

        .override-button {
          padding: 14px;
          border-radius: 10px;
          font-weight: 800;
          background: transparent;
        }

        .override-button.trusted {
          border: 1px solid #08733b;
          background: #033b20;
          color: #4ade80;
        }

        .override-button.suspicious {
          border: 1px solid #a34b08;
          background: #472004;
          color: #fbbf24;
        }

        .override-button.dangerous {
          border: 1px solid #a91f26;
          background: #4b0a0d;
          color: #f87171;
        }

        .control-note {
          margin-top: 35px;
          padding: 15px;
          color: #637998;
          font-size: 12px;
          line-height: 1.55;
          background: #0c1525;
          border-radius: 8px;
        }

        .content-panel {
          padding: 28px;
        }

        .panel-header {
          padding-bottom: 20px;
          border-bottom: 1px solid #1f2b40;
        }

        .history-list {
          padding-top: 5px;
        }

        .history-item {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 20px;
          padding: 18px 0;
          border-bottom: 1px solid #1b273b;
        }

        .history-item:last-child {
          border-bottom: 0;
        }

        .history-main {
          min-width: 0;
        }

        .history-url {
          overflow: hidden;
          color: #e5edf8;
          font-weight: 700;
          text-overflow: ellipsis;
          white-space: nowrap;
        }

        .history-meta {
          margin-top: 6px;
          color: #667b9b;
          font-size: 12px;
        }

        .history-right {
          display: flex;
          align-items: center;
          gap: 12px;
          flex-shrink: 0;
        }

        .empty-state {
          padding: 55px 20px;
          color: #667b9b;
          text-align: center;
        }

        .settings-grid {
          display: grid;
          grid-template-columns: repeat(2, 1fr);
          gap: 20px;
          padding-top: 25px;
        }

        .settings-card {
          padding: 25px;
          border: 1px solid #202d42;
          border-radius: 13px;
          background: #0d1626;
        }

        .settings-card h3 {
          margin-top: 0;
          color: #f8fafc;
        }

        .settings-row {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 20px;
          padding: 16px 0;
          border-bottom: 1px solid #1b273b;
        }

        .settings-name {
          color: #dce5f3;
          font-weight: 700;
          font-size: 14px;
        }

        .settings-value {
          margin-top: 5px;
          color: #7084a3;
          font-size: 12px;
        }

        .settings-card .secondary-button,
        .settings-card .danger-button {
          margin-top: 20px;
        }

        @media (max-width: 1050px) {
          .sidebar {
            width: 225px;
          }

          .main {
            padding: 35px 28px;
          }

          .analysis-layout {
            grid-template-columns: 1fr;
          }
        }

        @media (max-width: 800px) {
          .sidebar {
            display: none;
          }

          .stats-grid,
          .settings-grid {
            grid-template-columns: 1fr;
          }

          .main {
            padding: 25px 18px;
          }

          .hero,
          .scanner-header,
          .panel-header {
            align-items: flex-start;
            flex-direction: column;
          }

          .scanner-input-row {
            flex-direction: column;
          }

          .analysis-main {
            flex-direction: column;
            padding: 25px 0;
          }

          .history-item {
            align-items: flex-start;
            flex-direction: column;
          }

          .history-right {
            width: 100%;
            justify-content: space-between;
          }
        }
      `}</style>
    </div>
  );
}

export default App;