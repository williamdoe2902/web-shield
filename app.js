const form = document.getElementById("scan-form");
const targetInput = document.getElementById("target-url");
const scanButton = document.getElementById("scan-button");
const progressWrap = document.getElementById("scan-progress");
const errorBanner = document.getElementById("scan-error");
const findingsList = document.getElementById("findings-list");
const surfaceList = document.getElementById("surface-list");
const historyList = document.getElementById("history-list");
const reportButton = document.getElementById("download-report");
let latestScan = null;
let pollTimer = null;

const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
}[char]));

function showError(message) {
  errorBanner.textContent = message;
  errorBanner.hidden = false;
}

function updateDashboard(scan) {
  latestScan = scan;
  document.getElementById("stat-pages").textContent = scan.pagesScanned;
  document.getElementById("stat-forms").textContent = scan.forms.length;
  document.getElementById("stat-findings").textContent = scan.findings.length;
  document.getElementById("nav-count").textContent = scan.findings.length;
  document.getElementById("stat-date").textContent = scan.status === "completed" && scan.completedAt
    ? new Date(scan.completedAt * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    : "Running…";
  document.getElementById("stat-target").textContent = scan.target;
  const counts = ["High", "Medium", "Low"].map((level) =>
    `${scan.findings.filter((item) => item.severity === level).length} ${level.toLowerCase()}`,
  );
  document.getElementById("stat-severity").textContent = scan.status === "completed"
    ? counts.join(" · ")
    : "Scan in progress";
  renderFindings(scan.findings);
  renderSurface(scan.pages, scan.forms);
  reportButton.disabled = scan.status !== "completed";
}

function renderFindings(findings) {
  if (!findings.length) {
    findingsList.className = "empty-state";
    findingsList.innerHTML = '<div class="empty-icon">✓</div><strong>No observations yet</strong><p>Scan results will appear here.</p>';
    return;
  }
  findingsList.className = "finding-list";
  findingsList.innerHTML = findings.map((item) => `
    <article class="finding">
      <div class="finding-head"><div class="finding-title">${escapeHtml(item.title)}</div><span class="severity ${escapeHtml(item.severity.toLowerCase())}">${escapeHtml(item.severity)}</span></div>
      <div class="finding-url">${escapeHtml(item.url)}</div>
      <div class="finding-detail">${escapeHtml(item.evidence)}</div>
      <div class="finding-fix"><strong>Suggested fix:</strong> ${escapeHtml(item.recommendation)}</div>
    </article>`).join("");
}

function renderSurface(pages, forms) {
  document.getElementById("surface-count").textContent = pages.length + forms.length;
  if (!pages.length && !forms.length) {
    surfaceList.className = "empty-state compact";
    surfaceList.innerHTML = '<div class="empty-icon">◎</div><strong>No pages mapped</strong><p>Discovered pages and input forms will appear here.</p>';
    return;
  }
  surfaceList.className = "page-list";
  let html = "";
  if (pages.length) {
    html += `<div class="surface-subhead">Pages · ${pages.length}</div>`;
    html += pages.map((page) => `<div class="page-row"><span class="page-url">${escapeHtml(page.url)}</span><span class="page-status">${escapeHtml(page.status)}</span></div>`).join("");
  }
  if (forms.length) {
    html += `<div class="surface-subhead">Forms · ${forms.length}</div>`;
    html += forms.map((item) => `<div class="form-row">${escapeHtml(item.method.toUpperCase())} · ${escapeHtml(item.fields.length)} fields<small>${escapeHtml(item.action)}</small></div>`).join("");
  }
  surfaceList.innerHTML = html;
}

function renderHistory(scans) {
  document.getElementById("history-count").textContent = scans.length;
  if (!scans.length) return;
  historyList.className = "page-list";
  historyList.innerHTML = scans.map((scan) => `
    <div class="page-row">
      <span class="page-url">${escapeHtml(new Date(scan.startedAt * 1000).toLocaleString())} · ${escapeHtml(scan.target)}</span>
      <span class="page-status">${escapeHtml(scan.status === "completed" ? `${scan.findingCount} findings` : "Running")}</span>
    </div>`).join("");
}

async function loadHistory() {
  try {
    const response = await fetch("/api/scans", { cache: "no-store" });
    if (!response.ok) return;
    renderHistory(await response.json());
  } catch {
    // History is supplementary; the active scan results remain available.
  }
}

async function pollScan(id) {
  try {
    const response = await fetch(`/api/scans/${encodeURIComponent(id)}`, { cache: "no-store" });
    const scan = await response.json();
    if (!response.ok) throw new Error(scan.error || "Could not read scan status.");
    updateDashboard(scan);
    document.getElementById("progress-number").textContent = `${scan.progress}%`;
    document.getElementById("progress-bar").style.width = `${scan.progress}%`;
    document.getElementById("progress-label").textContent = scan.status === "completed"
      ? `Scan complete · ${scan.pagesScanned} pages mapped`
      : `Mapping local pages… ${scan.pagesScanned} found`;
    if (scan.status === "completed") {
      loadHistory();
      scanButton.disabled = false;
      scanButton.innerHTML = "Start scan <span>→</span>";
      if (scan.error) showError(`Some pages could not be scanned: ${scan.error}`);
      return;
    }
    pollTimer = window.setTimeout(() => pollScan(id), 800);
  } catch (error) {
    scanButton.disabled = false;
    scanButton.innerHTML = "Start scan <span>→</span>";
    showError(error.message);
  }
}

async function startScan(event) {
  event.preventDefault();
  window.clearTimeout(pollTimer);
  errorBanner.hidden = true;
  scanButton.disabled = true;
  scanButton.textContent = "Starting…";
  progressWrap.hidden = false;
  document.getElementById("progress-bar").style.width = "2%";
  try {
    const response = await fetch("/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: targetInput.value.trim() }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "The scan could not be started.");
    pollScan(result.id);
  } catch (error) {
    scanButton.disabled = false;
    scanButton.innerHTML = "Start scan <span>→</span>";
    progressWrap.hidden = true;
    showError(error.message);
  }
}

function exportReport() {
  if (!latestScan || latestScan.status !== "completed") return;
  const findings = latestScan.findings.map((item) => `
    <article><h2>${escapeHtml(item.title)} <small>${escapeHtml(item.severity)}</small></h2>
    <p><b>URL:</b> ${escapeHtml(item.url)}</p><p><b>Observation:</b> ${escapeHtml(item.evidence)}</p>
    <p><b>Suggested remediation:</b> ${escapeHtml(item.recommendation)}</p></article>`).join("");
  const pages = latestScan.pages.map((item) => `<li>${escapeHtml(item.status)} — ${escapeHtml(item.url)}</li>`).join("");
  const report = `<!doctype html><html lang="en"><meta charset="utf-8"><title>WebShield report</title>
  <style>body{font:15px Arial,sans-serif;max-width:900px;margin:40px auto;padding:0 20px;color:#172235}h1{color:#087f85}article{border-top:1px solid #ccd5df;padding:14px 0}small{font-size:12px;color:#68788c}li{margin:7px 0;overflow-wrap:anywhere}.note{background:#edf7f6;padding:12px}</style>
  <h1>WebShield Scan Report</h1><p><b>Target:</b> ${escapeHtml(latestScan.target)}</p>
  <p><b>Completed:</b> ${new Date(latestScan.completedAt * 1000).toLocaleString()}</p>
  <p><b>Pages:</b> ${latestScan.pages.length} &nbsp; <b>Forms:</b> ${latestScan.forms.length} &nbsp; <b>Observations:</b> ${latestScan.findings.length}</p>
  <div class="note">Passive local scan only: GET requests, no form submissions, and no SQLi, XSS, or traversal payloads. Observations require manual validation.</div>
  <h2>Findings</h2>${findings || "<p>No observations detected.</p>"}<h2>Mapped pages</h2><ul>${pages}</ul></html>`;
  const blob = new Blob([report], { type: "text/html;charset=utf-8" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = "webshield-scan-report.html";
  link.click();
  URL.revokeObjectURL(link.href);
}

form.addEventListener("submit", startScan);
document.getElementById("new-scan-top").addEventListener("click", () => targetInput.focus());
document.getElementById("new-scan-hero").addEventListener("click", () => {
  document.getElementById("scan-panel").scrollIntoView({ behavior: "smooth" });
  targetInput.focus({ preventScroll: true });
});
reportButton.addEventListener("click", exportReport);
loadHistory();
