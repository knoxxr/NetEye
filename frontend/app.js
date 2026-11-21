const assetList = document.getElementById("asset-list");
const assetDetail = document.getElementById("asset-detail");
const searchInput = document.getElementById("asset-search");
const alertsBody = document.getElementById("alerts-body");
const showAcked = document.getElementById("show-acked");
let latestSnapshot = { assets: [], links: [], alerts: [], stats: {}, sensor: {}, import: {} };
let selectedId = null;

const SEVERITY_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
const CATEGORY_LABEL = {
  read: "Read", monitor: "Monitor", session: "Session", discovery: "Discovery", diagnostic: "Diagnostic",
  write: "Write", command: "Command", config: "Configuration", program: "Program",
  control: "State Control", firmware: "Firmware",
};
const LEVEL_LABEL = {
  confirmed: "Confirmed", likely: "Likely", possible: "Possible",
  "확정": "Confirmed", "유력": "Likely", "가능": "Possible",
};

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]);
}

function nodeClass(asset) {
  const type = String(asset.device_type || "Unknown").toLowerCase();
  if (type.includes("plc")) return "node-type-plc";
  if (type.includes("rtu") || type.includes("ied") || type.includes("merging")) return "node-type-power";
  if (type.includes("workstation") || type.includes("hmi") || type.includes("scada")) return "node-type-workstation";
  if (type.includes("building")) return "node-type-building";
  if (type !== "unknown") return "node-type-industrial";
  return "node-type-unknown";
}

function shortType(asset) {
  return !asset.device_type || asset.device_type === "Unknown" ? "Unknown Asset" : asset.device_type;
}

const CRIT_LABEL = { low: "Low", medium: "Medium", high: "High", critical: "Critical" };
const MANUAL_FIELDS = ["name", "device_type", "vendor", "model", "firmware", "os", "location", "owner", "criticality", "notes"];

/** Name to show: what the operator entered, else the hostname, else the address. */
function displayName(asset) {
  return (asset.manual && asset.manual.name) || asset.hostname || asset.label;
}

function critBadge(asset) {
  const c = asset.manual && asset.manual.criticality;
  return c && CRIT_LABEL[c] ? `<span class="crit-badge crit-${escapeHtml(c)}" title="Criticality">${CRIT_LABEL[c]}</span>` : "";
}

/** Who an internet address belongs to: organization (AS) and the domain used to reach it. */
function orgText(asset) {
  const parts = [asset.org && asset.org.name, asset.domains && asset.domains[asset.domains.length - 1]].filter(Boolean);
  return parts.join(" · ");
}

function subtitle(asset) {
  const identity = [asset.vendor, asset.model].filter(Boolean).join(" ");
  const host = [asset.hostname, asset.os].filter(Boolean).join(" · ");
  return identity || host || orgText(asset) || shortType(asset);
}

function formatTime(value) {
  if (!value) return "";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString("en-US", {
    year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
  });
}

/** Asset by id, through an index built once per snapshot (lists and details look up many). */
const assetIndexes = new WeakMap();
function assetById(id) {
  let index = assetIndexes.get(latestSnapshot);
  if (!index) {
    index = new Map((latestSnapshot.assets || []).map((a) => [a.id, a]));
    assetIndexes.set(latestSnapshot, index);
  }
  return index.get(id);
}

function labelOf(id) {
  const asset = assetById(id);
  return asset ? asset.label : id || "-";
}

/** Who a peer is, in one short line: manual name / hostname, organization, domain. */
function peerDescription(id) {
  const asset = assetById(id);
  if (!asset) return "";
  const parts = [];
  const named = (asset.manual && asset.manual.name) || asset.hostname;
  if (named) parts.push(escapeHtml(named));
  if (asset.org) {
    parts.push(`${escapeHtml(asset.org.name)}${asset.org.well_known ? ' <span class="well">Well-known</span>' : ""}`);
  }
  const domain = (asset.domains || []).slice(-1)[0];
  if (domain) parts.push(`<span class="mono">${escapeHtml(domain)}</span>`);
  if (!parts.length && asset.device_type && asset.device_type !== "Unknown") parts.push(escapeHtml(asset.device_type));
  return parts.join(" · ");
}

/** Replace an element's markup only when it changed: avoids table flicker and preserves selection. */
const renderedHtml = new WeakMap();
function setHtml(element, html) {
  if (renderedHtml.get(element) === html) return;
  renderedHtml.set(element, html);
  element.innerHTML = html;
}

const graph = new NetGraph(document.querySelector(".graph-wrap"), {
  onSelect: (id) => {
    selectedId = id;
    render(latestSnapshot);
  },
});
const flowButton = document.getElementById("flow-toggle");
flowButton.setAttribute("aria-pressed", String(graph.flow));
flowButton.addEventListener("click", () => {
  graph.setFlow(!graph.flow);
  flowButton.setAttribute("aria-pressed", String(graph.flow));
});
document.getElementById("zoom-in").addEventListener("click", () => graph.zoomBy(1.3));
document.getElementById("zoom-out").addEventListener("click", () => graph.zoomBy(1 / 1.3));
document.getElementById("zoom-fit").addEventListener("click", () => graph.fit());
const graphPanel = document.querySelector(".graph-panel");
document.getElementById("graph-fullscreen").addEventListener("click", () => {
  if (document.fullscreenElement) document.exitFullscreen();
  else graphPanel.requestFullscreen?.().catch(() => {});
});
document.addEventListener("fullscreenchange", () => {
  setTimeout(() => graph.fit(), 50);
});
const graphMode = document.getElementById("graph-mode");
const graphExternal = document.getElementById("graph-external");
const graphIsolated = document.getElementById("graph-isolated");
function syncGraphOptions(options) {
  graphMode.value = options.mode;
  graphExternal.checked = options.collapseExternal;
  graphIsolated.checked = options.hideIsolated;
}
graph.onOptions = syncGraphOptions;
syncGraphOptions(graph.options);
graphMode.addEventListener("change", () => graph.setOption("mode", graphMode.value));
graphExternal.addEventListener("change", () => graph.setOption("collapseExternal", graphExternal.checked));
graphIsolated.addEventListener("change", () => graph.setOption("hideIsolated", graphIsolated.checked));

function searchText(asset) {
  const m = asset.manual || {};
  const org = asset.org || {};
  return [asset.label, asset.ip, asset.device_type, asset.vendor, asset.model, asset.name, asset.hostname, asset.os,
    org.name, org.holder, org.asn && `AS${org.asn}`, ...(asset.domains || []),
    m.name, m.location, m.owner, m.notes, CRIT_LABEL[m.criticality],
    asset.firmware, ...(asset.macs || []), ...(asset.protocols || [])].join(" ").toLowerCase();
}

function render(snapshot) {
  const fresh = snapshot !== latestSnapshot;
  latestSnapshot = snapshot;
  const assets = snapshot.assets || [];
  const query = searchInput.value.trim().toLowerCase();
  const visibleAssets = assets.filter((asset) => searchText(asset).includes(query));
  const visibleIds = new Set(visibleAssets.map((asset) => asset.id));
  const visibleLinks = (snapshot.links || []).filter((link) =>
    visibleIds.has(link.source) && visibleIds.has(link.target));
  const stats = snapshot.stats || {};

  document.getElementById("stat-assets").textContent = stats.asset_count ?? assets.length;
  document.getElementById("stat-ot-assets").textContent = stats.ot_asset_count ?? 0;
  document.getElementById("stat-links").textContent = stats.link_count ?? 0;
  document.getElementById("stat-alerts").textContent = stats.alert_open ?? 0;
  document.getElementById("stat-alerts-high").textContent = stats.alert_critical ?? 0;
  document.getElementById("asset-count-badge").textContent = visibleAssets.length;
  document.getElementById("empty-state").hidden = assets.length > 0;
  renderStatus(snapshot.sensor || {});
  renderImport(snapshot.import || {});
  renderBaseline(snapshot.baseline);
  renderVulns(snapshot);
  document.getElementById("stat-vuln").textContent = stats.vulnerable_assets ?? 0;
  document.getElementById("stat-kev").textContent = stats.kev_assets ?? 0;

  const alertPairs = new Set((snapshot.alerts || []).filter((a) => a.status === "new")
    .map((a) => `${a.src}|${a.dst}`));

  graph.update(visibleAssets, visibleLinks, alertPairs, selectedId, fresh);

  renderAssetList(visibleAssets);
  renderAssetDetail(assets.find((asset) => asset.id === selectedId));
  renderAlerts(snapshot.alerts || []);
  renderExternal(snapshot);
}

function renderStatus(sensor) {
  const pill = document.getElementById("sensor-status");
  const label = sensor.error ? "Sensor Error" : sensor.enabled ? "Live Capture Active" : "Live Capture Off";
  pill.className = `status-pill ${sensor.error ? "status-error" : sensor.enabled ? "status-online" : "status-offline"}`;
  pill.innerHTML = `<span class="status-dot"></span>${label}`;
  const interfaceLabel = sensor.interface
    ? `Capture interface: ${sensor.interface}`
    : "Set NETEYE_INTERFACE for live capture or upload a PCAP file";
  document.getElementById("capture-interface").textContent = sensor.error
    ? `${interfaceLabel} · ${sensor.error}` : interfaceLabel;
  pill.title = sensor.error || "";
}

function renderImport(state) {
  const el = document.getElementById("import-status");
  if (state.running) {
    el.textContent = `Analyzing ${state.file}… ${state.frames.toLocaleString()} frames`;
    el.className = "import-status running";
  } else if (state.error) {
    el.textContent = `Import failed: ${state.error}`;
    el.className = "import-status error";
  } else if (state.last_result) {
    el.textContent = `${state.last_result.file}: ${state.last_result.frames.toLocaleString()} frames analyzed`;
    el.className = "import-status";
  } else {
    el.textContent = "";
  }
}

function renderAssetList(assets) {
  if (assets.length === 0) {
    setHtml(assetList, '<div class="list-placeholder">No matching assets found.</div>');
    return;
  }
  setHtml(assetList, assets.map((asset) => `
    <button class="asset-row ${asset.id === selectedId ? "selected" : ""}" data-id="${escapeHtml(asset.id)}">
      <span class="asset-avatar ${nodeClass(asset)}">${asset.device_type === "Unknown" ? "?" : "◆"}</span>
      <span class="asset-row-copy">
        <strong>${escapeHtml(displayName(asset))}</strong>
        <span>${escapeHtml(displayName(asset) !== asset.label ? `${asset.label} · ${subtitle(asset)}` : subtitle(asset))}</span>
      </span>
      ${asset.risk_level && asset.risk_level !== "none" && (asset.vulns || []).some((v) => v.level !== "possible")
        ? `<span class="risk-badge sev-${escapeHtml(asset.risk_level)}" title="Vulnerability Risk Score">${asset.risk.toFixed(1)}</span>` : ""}
      ${critBadge(asset)}
      <i class="row-status ${asset.status === "stale" ? "stale" : ""}"></i>
    </button>`).join(""));
}

function detailItem(label, value) {
  return value ? `<div class="detail-item"><span>${label}</span><strong>${escapeHtml(value)}</strong></div>` : "";
}

function identityItem(asset, label, field) {
  const value = asset[field];
  const manual = asset.manual && asset.manual[field];
  const auto = asset.auto && asset.auto[field];
  if (!value) return "";
  const autoNote = manual && auto && auto !== manual ? `<small class="auto-value">Auto-detected: ${escapeHtml(auto)}</small>` : "";
  return `<div class="detail-item"><span>${label}${manual ? '<b class="manual-tag">Manual</b>' : ""}</span><strong>${escapeHtml(value)}</strong>${autoNote}</div>`;
}

function formatValue(v) {
  if (typeof v !== "number") return "-";
  return Number.isInteger(v) ? v.toLocaleString() : Number(v.toPrecision(6)).toString();
}

function pointsDetail(asset) {
  const points = asset.points || [];
  if (!points.length) return "";
  const rows = points.slice(0, 15).map((p) => {
    const learned = p.learned === 0 ? "Not learned"
      : p.stateful ? `Learned states {${(p.states || []).map(formatValue).join(", ")}}`
      : `Learned range ${formatValue(p.min)} ~ ${formatValue(p.max)}`;
    const kind = p.kind === "read" ? "Measure" : "Write";
    return `<li><span class="point-kind ${p.kind === "read" ? "read" : "write"}">${kind}</span> <b class="mono">${escapeHtml(p.point)}</b> = <span class="mono">${formatValue(p.last)}</span>
      <small>${escapeHtml(p.protocol)} · ${kind} ×${p.writes.toLocaleString()} · ${escapeHtml(learned)}</small></li>`;
  }).join("");
  const more = points.length > 15 ? `<small class="more">+${points.length - 15} more points</small>` : "";
  return `<div class="detail-item"><span>Process Points (Writes &amp; Measurements)</span><ul class="point-list">${rows}</ul>${more}</div>`;
}

function levelOf(score) {
  return score >= 70 ? ["lv-danger", "High Risk"] : score >= 30 ? ["lv-warn", "Warning"] : score > 0 ? ["lv-note", "Notice"] : ["lv-ok", "Normal"];
}

function externalDetail(asset) {
  if (!asset.org && !(asset.domains || []).length) return "";
  const ext = (latestSnapshot.external || []).find((e) => e.id === asset.id);
  const org = asset.org;
  const orgLine = org ? `${escapeHtml(org.name)}${org.well_known ? ' <span class="well">Well-known</span>' : ""}
      <small>AS${org.asn} · ${escapeHtml(org.holder)} · ${escapeHtml(org.country)}</small>` : "Unknown organization";
  const [cls, label] = levelOf(ext ? ext.score : 0);
  return `<div class="detail-item ext-org"><span>External Organization (ASN)</span><strong>${orgLine}</strong></div>
    ${(asset.domains || []).length ? detailItem("Observed Domains (DNS·SNI·Host)", asset.domains.join(", ")) : ""}
    ${ext ? `<div class="detail-item"><span>External Risk Rating</span><strong><span class="ext-level ${cls}">${label}</span></strong>
      ${ext.reasons.length ? `<small class="ext-reasons">${ext.reasons.map(escapeHtml).join("<br>")}</small>` : ""}</div>` : ""}`;
}

function vulnDetail(asset) {
  const vulns = asset.vulns || [];
  if (!vulns.length) return "";
  const items = vulns.slice(0, 8).map((v) => `<li>
      <span class="sev sev-${riskOf(v.score)}">${v.score.toFixed(1)}</span>
      ${advisoryLink(v)}${v.kev ? ' <span class="kev">KEV</span>' : ""}
      <span class="lvl lvl-${escapeHtml(v.level)}">${escapeHtml(LEVEL_LABEL[v.level] || LEVEL_LABEL[v.level_label] || v.level_label)}</span>
      <small>${escapeHtml(v.versions)} · ${escapeHtml((v.cves || []).slice(0, 3).join(", "))}</small>
    </li>`).join("");
  const more = vulns.length > 8 ? `<small class="more">+${vulns.length - 8} more — see Vulnerabilities table below</small>` : "";
  return `<div class="detail-item"><span>Vulnerabilities (Risk ${asset.risk.toFixed(1)})</span><ul class="vuln-list">${items}</ul>${more}</div>`;
}

const SOURCE_TAG = { policy: "Policy", baseline: "Baseline", anomaly: "Anomaly", external: "External" };

function profileText(profile) {
  if (!profile) return "";
  const parts = [];
  const interval = profile.interval || {};
  if (interval.n >= 20) {
    const std = interval.n > 1 ? Math.sqrt(interval.m2 / (interval.n - 1)) : 0;
    const fmt = (ms) => (ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${Math.round(ms)}ms`);
    parts.push(`Poll interval ${fmt(interval.mean)} ±${fmt(std)}`);
  }
  const volume = profile.volume || {};
  if (volume.n >= 5) parts.push(`${Math.round(volume.mean).toLocaleString()} pkt/min`);
  return parts.length ? `Learned: ${parts.join(" · ")}` : "";
}

function renderAssetDetail(asset) {
  if (!asset) {
    setHtml(assetDetail, '<div class="detail-placeholder"><span class="detail-placeholder-icon">◎</span><span>Select an asset from the map or list.</span></div>');
    return;
  }
  const confidence = Math.round((asset.confidence || 0) * 100);
  const evidence = (asset.evidence || []).length
    ? `<ul class="evidence-list">${asset.evidence.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`
    : "<span>No identification evidence observed yet.</span>";
  const allComms = (latestSnapshot.links || []).filter((l) => l.source === asset.id || l.target === asset.id)
    .sort((a, b) => b.packets - a.packets);
  const comms = allComms.slice(0, 40);
  const externalScore = new Map((latestSnapshot.external || []).map((e) => [e.id, e.score]));
  const commsHtml = comms.length ? comms.map((link) => {
    const outbound = link.source === asset.id;
    const peerId = outbound ? link.target : link.source;
    const peer = labelOf(peerId);
    const about = peerDescription(peerId);
    const score = externalScore.get(peerId);
    const [cls, level] = score !== undefined && score >= 30 ? levelOf(score) : ["", ""];
    const ops = Object.entries(link.operations || {}).sort((a, b) => b[1] - a[1]).slice(0, 6)
      .map(([op, n]) => `<li>${escapeHtml(op)} <em>×${n}</em></li>`).join("");
    const cats = Object.keys(link.categories || {}).map((c) => CATEGORY_LABEL[c] || c).join(", ");
    const profile = profileText(link.profile);
    return `<div class="comm">
      <div class="comm-head"><b>${outbound ? "→" : "←"} <a data-id="${escapeHtml(peerId)}">${escapeHtml(peer)}</a></b><span>${escapeHtml(link.protocol)}</span></div>
      ${about || level ? `<div class="comm-peer ext-org">${level ? `<span class="ext-level ${cls}">${level}</span> ` : ""}${about}</div>` : ""}
      ${cats ? `<div class="comm-cats">${escapeHtml(cats)}</div>` : ""}
      ${profile ? `<div class="comm-profile" title="Learned statistical baseline">${escapeHtml(profile)}</div>` : ""}
      ${ops ? `<ul class="op-list">${ops}</ul>` : ""}
    </div>`;
  }).join("") + (allComms.length > comms.length ? `<small class="more">Showing top ${comms.length} of ${allComms.length} links</small>` : "")
    : "<span>No communications observed.</span>";

  setHtml(assetDetail, `
    <div class="selected-asset">
      <div class="detail-title">
        <div>
          <h3>${escapeHtml(displayName(asset))} ${critBadge(asset)}</h3>
          ${displayName(asset) !== asset.label ? `<p class="asset-ip">${escapeHtml(asset.label)}</p>` : ""}
        </div>
        <button class="button ghost" data-edit-asset="${escapeHtml(asset.id)}" data-min-role="operator">Edit Info</button>
      </div>
      <p class="asset-type">${escapeHtml(shortType(asset))}${asset.manual && asset.manual.device_type ? ' <b class="manual-tag">Manual</b>' : ""}</p>
      <div class="detail-grid">
        ${asset.manual && asset.manual.device_type
          ? `<div class="detail-item"><span>Confidence</span><strong>Manual Override</strong><small class="auto-value">Auto-detected: ${escapeHtml(asset.auto ? asset.auto.device_type : "")} (${confidence}%)</small></div>`
          : `<div class="detail-item"><span>Identification Confidence</span><strong>${confidence}%</strong><div class="confidence-track"><i style="width:${confidence}%"></i></div></div>`}
        ${asset.manual && asset.manual.location ? detailItem("Location", asset.manual.location) : ""}
        ${asset.manual && asset.manual.owner ? detailItem("Owner", asset.manual.owner) : ""}
        ${asset.manual && asset.manual.notes ? `<div class="detail-item"><span>Notes</span><strong class="notes">${escapeHtml(asset.manual.notes)}</strong></div>` : ""}
        ${externalDetail(asset)}
        ${detailItem("Hostname", asset.hostname)}
        ${asset.manual && asset.manual.os ? identityItem(asset, "Operating System", "os")
          : asset.os ? `<div class="detail-item"><span>Operating System (Passive ${Math.round(asset.os_confidence * 100)}%)</span><strong>${escapeHtml(asset.os)}</strong><small class="os-evidence">${escapeHtml(asset.os_evidence)}</small></div>` : ""}
        ${identityItem(asset, "Vendor", "vendor")}
        ${identityItem(asset, "Model / Order Number", "model")}
        ${detailItem("Product Code", asset.product_code)}
        ${identityItem(asset, "Firmware", "firmware")}
        ${detailItem("Serial Number", asset.serial)}
        ${detailItem("Station Name", asset.name)}
        ${detailItem("Description", asset.description)}
        ${detailItem("MAC Address", (asset.macs || []).join(", ") || "Unknown")}
        ${detailItem("VLAN", (asset.vlans || []).join(", "))}
        ${detailItem("Roles", (asset.roles || []).join(", "))}
        ${detailItem("Observed Protocols", (asset.protocols || []).join(", "))}
        ${vulnDetail(asset)}
        ${pointsDetail(asset)}
        <div class="detail-item"><span>Identification Evidence</span>${evidence}</div>
        <div class="detail-item"><span>Communications &amp; Commands</span>${commsHtml}</div>
        ${detailItem("Packets / Bytes", `${asset.packets.toLocaleString()} / ${asset.bytes.toLocaleString()}`)}
        <div class="detail-item"><span>First / Last Seen</span><strong>${escapeHtml(formatTime(asset.first_seen))}<br>${escapeHtml(formatTime(asset.last_seen))}</strong></div>
        ${asset.manual && asset.manual.updated_by ? detailItem("Last Edited", `${asset.manual.updated_by} · ${formatTime(asset.manual.updated_at)}`) : ""}
      </div>
    </div>`);
}

const alertSource = document.getElementById("alert-source");
const ROLE_RANK = { viewer: 0, operator: 1, admin: 2 };
const ROLE_LABEL = { viewer: "Viewer", operator: "Operator", admin: "Admin" };
let currentUser = null;

function can(role) {
  return currentUser && ROLE_RANK[currentUser.role] >= ROLE_RANK[role];
}

async function api(url, options) {
  const response = await fetch(url, options);
  if (response.status === 401) {
    location.replace("/login.html");
    throw new Error("session expired");
  }
  return response;
}
const vulnLevel = document.getElementById("vuln-level");
const vulnsBody = document.getElementById("vulns-body");

function vulnRows(assets) {
  const filter = vulnLevel.value;
  const rows = [];
  assets.forEach((asset) => (asset.vulns || []).forEach((v) => {
    if (filter === "solid" && v.level === "possible") return;
    if (filter === "kev" && !(v.kev && v.level !== "possible")) return;
    rows.push({ asset, v });
  }));
  return rows.sort((a, b) => b.v.score - a.v.score);
}

function riskOf(score) {
  return score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : "low";
}

function advisoryLink(v) {
  const safe = /^https:\/\//.test(v.url || "") ? v.url : "";
  return safe ? `<a href="${escapeHtml(safe)}" target="_blank" rel="noopener noreferrer">${escapeHtml(v.id)}</a>` : escapeHtml(v.id);
}

function renderVulns(snapshot) {
  const db = snapshot.vulndb;
  const state = snapshot.vulndb_state || {};
  const info = document.getElementById("vulndb-info");
  if (db) {
    info.textContent = `${db.advisory_count.toLocaleString()} CISA ICS Advisories · KEV Catalog ${db.sources?.kev_catalog_version || "-"} · Built ${formatTime(db.built_at)}`;
  } else if (state.error) {
    info.textContent = `Failed to load Vulnerability DB: ${state.error}`;
  }
  const rows = vulnRows(snapshot.assets || []);
  if (rows.length === 0) {
    setHtml(vulnsBody, `<tr><td colspan="7" class="empty-row">${db ? "No matching vulnerabilities for the current filter." : "Upload vulndb.json to match discovered assets offline."}</td></tr>`);
    return;
  }
  setHtml(vulnsBody, rows.slice(0, 300).map(({ asset, v }) => `
    <tr>
      <td><span class="sev sev-${riskOf(v.score)}">${v.score.toFixed(1)}</span></td>
      <td class="mono"><a data-id="${escapeHtml(asset.id)}">${escapeHtml(asset.label)}</a><small>${escapeHtml([asset.model, asset.firmware].filter(Boolean).join(" · "))}</small></td>
      <td>${advisoryLink(v)}${v.kev ? ' <span class="kev">KEV</span>' : ""}<small>${escapeHtml(v.title)}</small></td>
      <td>${escapeHtml(v.product)}<small>${escapeHtml(v.versions)}</small></td>
      <td class="mono">${escapeHtml(v.cvss ?? "-")}</td>
      <td><span class="lvl lvl-${escapeHtml(v.level)}">${escapeHtml(LEVEL_LABEL[v.level] || LEVEL_LABEL[v.level_label] || v.level_label)}</span></td>
      <td class="fix">${escapeHtml(v.remediation || "-")}</td>
    </tr>`).join(""));
}

function renderBaseline(baseline) {
  if (!baseline) return;
  const learning = baseline.mode === "learning";
  const bar = document.getElementById("baseline-bar");
  bar.className = `baseline-bar ${learning ? "mode-learning" : "mode-detecting"}`;
  document.getElementById("mode-badge").textContent = learning ? "Learning" : "Detecting";
  let title = learning ? "Learning Normal Traffic" : "Detecting Baseline Deviations";
  if (learning && baseline.learning_until) {
    const left = Math.max(0, baseline.learning_until * 1000 - Date.now());
    const hours = Math.floor(left / 3600000), minutes = Math.ceil((left % 3600000) / 60000);
    title += ` · Auto-switches to Detection in ${hours ? `${hours}h ` : ""}${minutes}m`;
  }
  document.getElementById("mode-title").textContent = title;
  const sinceStr = baseline.mode_since ? formatTime(new Date(baseline.mode_since * 1000).toISOString()) : "-";
  document.getElementById("mode-desc").textContent = learning
    ? "Observed assets, links, and commands are recorded as baseline behavior. Risky command policy alerts remain active."
    : `Alerting on unseen assets, links, and commands since ${sinceStr}.`;
  const counts = baseline.counts || {};
  document.getElementById("bl-assets").textContent = (counts.asset ?? 0).toLocaleString();
  document.getElementById("bl-links").textContent = (counts.link ?? 0).toLocaleString();
  document.getElementById("bl-ops").textContent = (counts.op ?? 0).toLocaleString();
  document.getElementById("btn-detect").hidden = !learning;
  document.getElementById("btn-learn").hidden = learning;
  document.getElementById("learn-hours").hidden = learning;
}

async function setMode(mode, reset = false) {
  const hours = document.getElementById("learn-hours").value;
  const body = { mode, reset };
  if (mode === "learning" && hours) body.hours = Number(hours);
  const response = await api("/api/baseline/mode", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  if (!response.ok) alert(`Failed to change baseline mode (${response.status})`);
  await loadSnapshot();
}

const externalFilter = document.getElementById("external-filter");
const externalBody = document.getElementById("external-body");

function formatPackets(n) {
  return n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e4 ? `${(n / 1e3).toFixed(0)}k` : n.toLocaleString();
}

function renderExternal(snapshot) {
  const rows = (snapshot.external || []).filter((e) => {
    if (externalFilter.value === "flagged") return e.score >= 30;
    if (externalFilter.value === "unknown") return !(e.org && e.org.well_known);
    return true;
  });
  const intel = snapshot.intel || {};
  const all = snapshot.external || [];
  const flagged = all.filter((e) => e.score >= 30).length;
  document.getElementById("external-info").textContent =
    `${all.length.toLocaleString()} External IPs · ${flagged} Flagged · `
    + (intel.asn ? `ASN DB ${intel.asn.ranges.toLocaleString()} ranges` : "No ASN DB (tools/ipasn_build.py)")
    + " · " + (intel.blocklist ? `Blocklist ${intel.blocklist.entries.toLocaleString()} entries` : "No Blocklist (tools/threatintel_build.py)");
  if (!rows.length) {
    setHtml(externalBody, `<tr><td colspan="7" class="empty-row">${all.length ? "No external connections match this filter." : "No internet communications observed yet."}</td></tr>`);
    return;
  }
  setHtml(externalBody, rows.slice(0, 300).map((e) => {
    const [cls, label] = levelOf(e.score);
    const org = e.org ? `<b>${escapeHtml(e.org.name)}</b>${e.org.well_known ? '<span class="well">Well-known</span>' : ""}
        <small>AS${e.org.asn} · ${escapeHtml(e.org.country)}</small>` : '<span class="muted">Unknown org</span>';
    const names = e.domains.length ? `<small>${escapeHtml(e.domains.slice(-3).join(", "))}</small>` : "";
    const services = e.services.map((s) => `<span class="svc ${s.inbound ? "in" : ""}" title="${s.inbound ? (s.accepted ? "Inbound connection accepted by internal host" : "Inbound connection attempt") : "Outbound connection"}">
        ${s.inbound ? "↘ " : ""}${s.port}/${s.tcp ? "TCP" : "UDP"}${s.name ? ` ${escapeHtml(s.name)}` : ""}</span>`).join("");
    const peers = e.peers.map((p) => `<a data-id="${escapeHtml(p)}">${escapeHtml(labelOf(p))}</a>`).join(", ")
      + (e.peer_count > e.peers.length ? ` +${e.peer_count - e.peers.length}` : "");
    return `<tr>
      <td><span class="ext-level ${cls}" title="Risk score ${e.score}">${label}</span>
        ${e.reasons.length ? `<small class="ext-reasons">${e.reasons.slice(0, 4).map(escapeHtml).join("<br>")}</small>` : ""}</td>
      <td class="mono"><a data-id="${escapeHtml(e.id)}">${escapeHtml(e.ip)}</a>${e.threat ? ' <span class="kev">Blocklist</span>' : ""}</td>
      <td class="ext-org">${org}${names}</td>
      <td class="mono">${peers}</td>
      <td>${services}</td>
      <td class="mono">${formatPackets(e.packets_out)} / ${formatPackets(e.packets_in)}</td>
      <td class="mono">${escapeHtml(formatTime(e.last_seen))}</td>
    </tr>`;
  }).join(""));
}

function renderAlerts(alerts) {
  const source = alertSource.value;
  const rows = alerts.filter((a) => (showAcked.checked || a.status === "new") && (!source || a.source === source));
  if (rows.length === 0) {
    setHtml(alertsBody, `<tr><td colspan="8" class="empty-row">No alerts to display.</td></tr>`);
    return;
  }
  setHtml(alertsBody, rows.slice(0, 200).map((a) => {
    const cat = CATEGORY_LABEL[a.category] || a.category_label || "";
    return `
    <tr class="${a.status === "acknowledged" ? "acked" : ""}">
      <td><span class="sev sev-${escapeHtml(a.severity)}">${escapeHtml(SEVERITY_LABEL[a.severity] || a.severity)}</span></td>
      <td><span class="src-tag src-${SOURCE_TAG[a.source] ? a.source : "policy"}">${SOURCE_TAG[a.source] || "Policy"}</span></td>
      <td><strong>${escapeHtml(a.title)}</strong>${cat ? `<small>${escapeHtml(cat)}</small>` : ""}</td>
      <td class="mono"><a data-id="${escapeHtml(a.src)}">${escapeHtml(labelOf(a.src))}</a>${a.dst ? ` → <a data-id="${escapeHtml(a.dst)}">${escapeHtml(labelOf(a.dst))}</a>` : ""}</td>
      <td>${escapeHtml(a.protocol)}</td>
      <td class="mono">${a.count}</td>
      <td class="mono">${escapeHtml(formatTime(a.last_seen))}</td>
      <td class="actions">${a.status !== "new" ? "Acknowledged" : !can("operator") ? "" :
        `${a.baseline ? `<button class="ack learn" data-learn="${a.id}" title="Add this behavior to the baseline">Learn</button>` : ""}<button class="ack" data-ack="${a.id}">Ack</button>`}</td>
    </tr>`;
  }).join(""));
}

document.addEventListener("click", async (event) => {
  const learn = event.target.closest("[data-learn]");
  if (learn) {
    learn.disabled = true;
    try {
      const res = await api(`/api/alerts/${learn.dataset.learn}/learn`, { method: "POST" });
      if (!res.ok) learn.disabled = false;
      await loadSnapshot();
    } catch {
      learn.disabled = false;
    }
    return;
  }
  const ack = event.target.closest("[data-ack]");
  if (ack) {
    ack.disabled = true;
    try {
      const res = await api(`/api/alerts/${ack.dataset.ack}/ack`, { method: "POST" });
      if (!res.ok) ack.disabled = false;
      await loadSnapshot();
    } catch {
      ack.disabled = false;
    }
    return;
  }
  const target = event.target.closest("[data-id]");
  if (target) {
    selectedId = target.dataset.id;
    render(latestSnapshot);
  }
});
searchInput.addEventListener("input", () => render(latestSnapshot));
showAcked.addEventListener("change", () => render(latestSnapshot));
alertSource.addEventListener("change", () => render(latestSnapshot));
vulnLevel.addEventListener("change", () => render(latestSnapshot));
externalFilter.addEventListener("change", () => render(latestSnapshot));
document.getElementById("vulndb-input").addEventListener("change", async (event) => {
  const file = event.target.files[0];
  event.target.value = "";
  if (!file) return;
  const info = document.getElementById("vulndb-info");
  info.textContent = `Uploading & matching ${file.name}…`;
  const response = await api("/api/vulndb", { method: "POST", headers: { "Content-Type": "application/json" }, body: file });
  if (!response.ok) {
    const detail = await response.json().catch(() => ({}));
    info.textContent = `Upload failed: ${detail.detail || response.status}`;
    return;
  }
  await loadSnapshot();
});
document.getElementById("btn-detect").addEventListener("click", () => setMode("detecting"));
document.getElementById("btn-learn").addEventListener("click", () => setMode("learning"));
document.getElementById("btn-reset").addEventListener("click", () => {
  if (confirm("Clear the entire baseline and restart learning from scratch? All subsequent observed traffic will be learned as normal.")) {
    setMode("learning", true);
  }
});

document.getElementById("pcap-input").addEventListener("change", async (event) => {
  const file = event.target.files[0];
  event.target.value = "";
  if (!file) return;
  const status = document.getElementById("import-status");
  status.textContent = `Uploading ${file.name}…`;
  status.className = "import-status running";
  const response = await api("/api/pcap", {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream", "X-Filename": encodeURIComponent(file.name) },
    body: file,
  });
  if (!response.ok) {
    const detail = await response.json().catch(() => ({}));
    status.textContent = `Upload failed: ${detail.detail || response.status}`;
    status.className = "import-status error";
  }
});

async function loadSnapshot() {
  const response = await api("/api/snapshot");
  if (!response.ok) throw new Error(`Snapshot request failed: ${response.status}`);
  render(await response.json());
}

let wsRetryDelay = 2000;
function connect() {
  const scheme = location.protocol === "https:" ? "wss:" : "ws:";
  const socket = new WebSocket(`${scheme}//${location.host}/ws`);
  socket.addEventListener("open", () => { wsRetryDelay = 2000; });
  socket.addEventListener("message", (event) => {
    try { render(JSON.parse(event.data)); } catch {}
  });
  socket.addEventListener("close", () => {
    setTimeout(() => {
      api("/api/session").then(() => connect(), (err) => {
        if (err && err.message === "session expired") return;
        wsRetryDelay = Math.min(30000, Math.round(wsRetryDelay * 1.5));
        connect();
      });
    }, wsRetryDelay);
  });
  socket.addEventListener("error", () => socket.close());
}

// ------------------------------------------------------------ support menu & version/updates
const supportBtn = document.getElementById("btn-support");
const supportDropdown = document.getElementById("support-dropdown");
function closeSupportMenu() {
  supportDropdown.hidden = true;
  supportBtn.setAttribute("aria-expanded", "false");
}
supportBtn.addEventListener("click", (event) => {
  event.stopPropagation();
  const next = !supportDropdown.hidden;
  supportDropdown.hidden = next;
  supportBtn.setAttribute("aria-expanded", String(!next));
});
document.addEventListener("click", (event) => {
  if (!event.target.closest("#support-menu")) closeSupportMenu();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeSupportMenu();
});

function syncSupportUrls(info) {
  if (!info) return;
  const setHref = (id, url) => {
    const el = document.getElementById(id);
    if (el && url && /^https:\/\//.test(url)) el.href = url;
  };
  setHref("link-github-issues", info.issues_url);
  setHref("link-github-discussions", info.discussions_url);
  setHref("link-github-releases", info.releases_url);
  setHref("btn-panel-issues", info.issues_url);
  setHref("btn-panel-discussions", info.discussions_url);
  setHref("footer-issues", info.issues_url);
  setHref("footer-discussions", info.discussions_url);
  setHref("footer-releases", info.releases_url);
}

function renderVersionPill(info) {
  if (!info) return;
  const ver = info.version || info.current_version || "0.1.0";
  const pill = document.getElementById("version-pill");
  if (pill) {
    pill.textContent = info.update_available && info.latest_version
      ? `v${ver} → v${info.latest_version}`
      : `v${ver}`;
    pill.classList.toggle("has-update", Boolean(info.update_available));
    pill.title = info.update_available
      ? `Update available: v${info.latest_version}`
      : `NetEye v${ver} (${info.platform}/${info.arch})`;
    if (!can("admin") && info.releases_url && /^https:\/\//.test(info.releases_url)) {
      pill.href = info.releases_url;
      pill.target = "_blank";
      pill.rel = "noopener noreferrer";
    }
  }
  const footer = document.getElementById("footer-brand");
  if (footer) footer.textContent = `NetEye v${ver} · Packet payloads are never stored.`;
  syncSupportUrls(info);
}

function renderUpdatePanel(info) {
  if (!info) return;
  renderVersionPill(info);
  document.getElementById("upd-current").textContent = `v${info.current_version}`;
  document.getElementById("upd-latest").textContent = info.latest_version ? `v${info.latest_version}` : "Not checked";
  document.getElementById("upd-platform").textContent = `${info.platform}/${info.arch}`;
  document.getElementById("upd-checked").textContent = info.last_checked ? formatTime(info.last_checked) : "Never";

  const summary = document.getElementById("update-summary");
  summary.textContent = info.status_message
    || `Repository: ${info.repo} · Checks GitHub Releases and verifies SHA-256 checksums before updating.`;

  const statusEl = document.getElementById("update-status-msg");
  statusEl.textContent = info.last_error || (info.restart_required ? "Update staged — restart NetEye service to activate." : "");
  statusEl.className = `import-status ${info.last_error ? "error" : info.restart_required ? "running" : ""}`;

  const applyBtn = document.getElementById("btn-apply-update");
  applyBtn.hidden = !(info.update_available && info.asset_url);
  applyBtn.disabled = Boolean(info.applying);
  applyBtn.textContent = info.applying
    ? "Downloading & Installing…"
    : info.can_self_update ? `Install v${info.latest_version}` : `Download v${info.latest_version}`;

  const relLink = document.getElementById("link-download-release");
  if (info.release_url && /^https:\/\//.test(info.release_url)) {
    relLink.href = info.release_url;
    relLink.hidden = false;
  } else {
    relLink.hidden = true;
  }

  document.getElementById("opt-auto-check").checked = Boolean(info.auto_check);
  const autoApply = document.getElementById("opt-auto-apply");
  autoApply.checked = Boolean(info.auto_apply);
  autoApply.disabled = !info.can_self_update;

  const notes = document.getElementById("update-notes");
  if (info.release_notes && info.release_notes.trim()) {
    notes.textContent = info.release_notes;
    notes.hidden = false;
  } else {
    notes.hidden = true;
  }
}

async function loadVersion() {
  const res = await api("/api/version");
  if (res.ok) renderVersionPill(await res.json());
}

async function loadUpdateStatus() {
  if (!can("admin")) return;
  const res = await api("/api/update");
  if (res.ok) renderUpdatePanel(await res.json());
}

document.getElementById("btn-check-update").addEventListener("click", async () => {
  const btn = document.getElementById("btn-check-update");
  const statusEl = document.getElementById("update-status-msg");
  btn.disabled = true;
  statusEl.textContent = "Checking GitHub Releases…";
  statusEl.className = "import-status running";
  try {
    const res = await api("/api/update/check", { method: "POST" });
    if (res.ok) renderUpdatePanel(await res.json());
  } finally {
    btn.disabled = false;
  }
});

document.getElementById("btn-apply-update").addEventListener("click", async () => {
  if (!confirm("Download, verify SHA-256 checksum, and install the latest NetEye release?")) return;
  const btn = document.getElementById("btn-apply-update");
  const statusEl = document.getElementById("update-status-msg");
  btn.disabled = true;
  statusEl.textContent = "Downloading and verifying update…";
  statusEl.className = "import-status running";
  try {
    const res = await api("/api/update/apply", { method: "POST" });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      statusEl.textContent = data.detail || `Update failed (${res.status})`;
      statusEl.className = "import-status error";
      btn.disabled = false;
      return;
    }
    renderUpdatePanel(data);
  } catch (err) {
    statusEl.textContent = `Update failed: ${err.message}`;
    statusEl.className = "import-status error";
    btn.disabled = false;
  }
});

async function saveUpdateSettings() {
  const res = await api("/api/update/settings", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      auto_check: document.getElementById("opt-auto-check").checked,
      auto_apply: document.getElementById("opt-auto-apply").checked,
    }),
  });
  if (res.ok) {
    const data = await res.json();
    renderUpdatePanel(data);
    if (data.warning) alert(data.warning);
  }
}
document.getElementById("opt-auto-check").addEventListener("change", saveUpdateSettings);
document.getElementById("opt-auto-apply").addEventListener("change", saveUpdateSettings);

// ------------------------------------------------------------ account
function renderUsers(users) {
  setHtml(document.getElementById("users-body"), users.map((u) => `
    <tr>
      <td class="mono">${escapeHtml(u.username)}${u.username === currentUser.username ? " (you)" : ""}</td>
      <td><select data-user-role="${escapeHtml(u.username)}">
        ${Object.keys(ROLE_LABEL).map((r) => `<option value="${r}" ${r === u.role ? "selected" : ""}>${ROLE_LABEL[r]}</option>`).join("")}
      </select></td>
      <td>${u.must_change ? "Password change required" : "Active"}</td>
      <td class="mono">${escapeHtml(formatTime(u.created))}</td>
      <td class="actions">
        <button class="ack" data-user-reset="${escapeHtml(u.username)}">Reset Password</button>
        ${u.username === currentUser.username ? "" : `<button class="ack" data-user-delete="${escapeHtml(u.username)}">Delete</button>`}
      </td>
    </tr>`).join(""));
}

function renderAudit(rows) {
  setHtml(document.getElementById("audit-body"), rows.length ? rows.map((r) => `
    <tr class="${r.status >= 400 ? "audit-fail" : ""}">
      <td class="mono">${escapeHtml(formatTime(r.ts))}</td>
      <td class="mono">${escapeHtml(r.username)}</td>
      <td class="mono">${escapeHtml(r.ip)}</td>
      <td>${escapeHtml(r.action)}${r.detail ? `<small>${escapeHtml(r.detail)}</small>` : ""}</td>
      <td class="mono">${r.status}</td>
    </tr>`).join("") : '<tr><td colspan="5" class="empty-row">No audit entries yet.</td></tr>');
}

function renderSiem(info) {
  const el = document.getElementById("siem-status");
  const syslog = info && info.syslog;
  if (!syslog) {
    setHtml(el, '<strong>SIEM Integration</strong><span>Not configured — set NETEYE_SYSLOG=udp://host:514,tcp://host:601 to forward alerts and audit logs as syslog (CEF/JSON).</span>');
    return;
  }
  setHtml(el, `<strong>SIEM Integration · ${escapeHtml(syslog.format.toUpperCase())}</strong>` + syslog.destinations.map((d) => {
    const state = d.transport === "udp" ? "UDP (unacknowledged)" : d.connected ? "Connected" : "Disconnected";
    const cls = d.transport === "udp" ? "" : d.connected ? "ok" : "bad";
    return `<span class="siem-dest ${cls}"><b class="mono">${escapeHtml(d.url)}</b> ${state} · Sent ${d.sent.toLocaleString()} · Queued ${d.queued}${d.dropped ? ` · Dropped ${d.dropped}` : ""}${d.last_error ? ` · ${escapeHtml(d.last_error)}` : ""}</span>`;
  }).join(""));
}

let captureChoicesLoaded = false;

async function loadCaptureSettings() {
  const response = await api("/api/sensor");
  if (!response.ok) return;
  const data = await response.json();
  const select = document.getElementById("capture-interface-select");
  const current = data.sensor && data.sensor.interface;
  const options = [`<option value="">Disabled (PCAP analysis only)</option>`].concat(data.interfaces.map((d) =>
    `<option value="${escapeHtml(d.name)}" ${d.name === current ? "selected" : ""}>${escapeHtml(d.description || d.name)}</option>`));
  if (!captureChoicesLoaded || !select.matches(":focus")) {
    select.innerHTML = options.join("");
    captureChoicesLoaded = true;
  }
  const status = document.getElementById("capture-form-status");
  status.textContent = data.error ? `Capture driver: ${data.error}`
    : `${data.sensor.enabled ? "Capturing" : current ? "Starting or error" : "Capture off"}${data.sensor.error ? ` · ${data.sensor.error}` : ""}`
      + (data.config_file ? ` · Config ${data.config_file}` : "");
  status.className = `import-status ${data.error || data.sensor.error ? "error" : ""}`;
}

document.getElementById("capture-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const select = document.getElementById("capture-interface-select");
  const response = await api("/api/sensor/capture", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ interface: select.value || null }),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) alert(data.detail || `Failed to apply capture interface (${response.status})`);
  else if (data.warning) alert(data.warning);
  setTimeout(loadCaptureSettings, 1500);
});

async function loadAdmin() {
  if (!can("admin")) return;
  loadCaptureSettings();
  loadUpdateStatus();
  const [users, audit, integrations] = await Promise.all([api("/api/users"), api("/api/audit?limit=100"), api("/api/integrations")]);
  if (users.ok) renderUsers(await users.json());
  if (audit.ok) renderAudit(await audit.json());
  if (integrations.ok) renderSiem(await integrations.json());
}

async function adminRequest(url, method, body) {
  const response = await api(url, {
    method, headers: { "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) alert(data.detail || `Request failed (${response.status})`);
  await loadAdmin();
  return response.ok;
}

document.getElementById("user-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const status = document.getElementById("user-form-status");
  const ok = await adminRequest("/api/users", "POST", {
    username: document.getElementById("new-username").value,
    password: document.getElementById("new-user-password").value,
    role: document.getElementById("new-user-role").value,
  });
  if (ok) {
    event.target.reset();
    status.textContent = "User added — password change required on first sign-in";
  }
});

document.addEventListener("change", (event) => {
  const select = event.target.closest("[data-user-role]");
  if (select) adminRequest(`/api/users/${encodeURIComponent(select.dataset.userRole)}`, "POST", { role: select.value });
});

document.addEventListener("click", (event) => {
  const reset = event.target.closest("[data-user-reset]");
  if (reset) {
    const password = prompt(`Temporary password for ${reset.dataset.userReset} (10+ characters). Must be changed on next sign-in.`);
    if (password) adminRequest(`/api/users/${encodeURIComponent(reset.dataset.userReset)}`, "POST", { password });
  }
  const del = event.target.closest("[data-user-delete]");
  if (del && confirm(`Delete user ${del.dataset.userDelete}? Active sessions will be terminated immediately.`)) {
    adminRequest(`/api/users/${encodeURIComponent(del.dataset.userDelete)}`, "DELETE");
  }
});

// ------------------------------------------------------------ asset editing
const assetDialog = document.getElementById("asset-dialog");
const assetForm = document.getElementById("asset-form");
let editingAsset = null;

function openAssetEditor(id) {
  const asset = (latestSnapshot.assets || []).find((a) => a.id === id);
  if (!asset) return;
  editingAsset = asset;
  const manual = asset.manual || {};
  const auto = asset.auto || { device_type: asset.device_type, vendor: asset.vendor, model: asset.model,
    firmware: asset.firmware, os: asset.os };
  const autoName = asset.hostname || asset.label;
  MANUAL_FIELDS.forEach((field) => {
    const input = assetForm.elements[field];
    input.value = manual[field] || "";
    if (input.tagName !== "SELECT" && field !== "notes") {
      const hint = field === "name" ? autoName : auto[field];
      input.placeholder = hint && hint !== "Unknown" ? `Auto: ${hint}` : field === "name" ? "e.g. Boiler #2 Main PLC" : "";
    }
  });
  document.getElementById("asset-dialog-id").textContent = asset.label;
  document.getElementById("asset-dialog-meta").textContent = manual.updated_by
    ? `Last edited by ${manual.updated_by} · ${formatTime(manual.updated_at)}` : "";
  document.getElementById("asset-error").hidden = true;
  assetDialog.showModal();
  assetForm.elements.name.focus();
}

async function saveAsset(values) {
  const error = document.getElementById("asset-error");
  const response = await api(`/api/assets/${encodeURIComponent(editingAsset.id)}/manual`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(values),
  });
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    error.textContent = `Save failed: ${data.detail || response.status}`;
    error.hidden = false;
    return;
  }
  assetDialog.close();
  await loadSnapshot();
}

document.addEventListener("click", (event) => {
  const edit = event.target.closest("[data-edit-asset]");
  if (edit) openAssetEditor(edit.dataset.editAsset);
});
assetForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const values = Object.fromEntries(MANUAL_FIELDS.map((f) => [f, assetForm.elements[f].value]));
  saveAsset(values);
});
document.getElementById("asset-cancel").addEventListener("click", () => assetDialog.close());
document.getElementById("asset-clear").addEventListener("click", () => {
  if (confirm("Clear all manually entered values for this asset and revert to auto-detected values?")) saveAsset({});
});

document.getElementById("btn-logout").addEventListener("click", async () => {
  await fetch("/api/logout", { method: "POST" });
  location.replace("/login.html");
});

const passwordDialog = document.getElementById("password-dialog");
document.getElementById("btn-password").addEventListener("click", () => {
  document.getElementById("password-form").reset();
  document.getElementById("pw-error").hidden = true;
  passwordDialog.showModal();
});
document.getElementById("pw-cancel").addEventListener("click", () => passwordDialog.close());
document.getElementById("password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const error = document.getElementById("pw-error");
  const next = document.getElementById("pw-new").value;
  if (next !== document.getElementById("pw-confirm").value) {
    error.textContent = "New passwords do not match.";
    error.hidden = false;
    return;
  }
  const response = await api("/api/password", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ current: document.getElementById("pw-current").value, new: next }),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    error.textContent = data.detail || `Password change failed (${response.status})`;
    error.hidden = false;
    return;
  }
  passwordDialog.close();
  alert("Password updated. Other active sessions have been signed out.");
});

async function start() {
  const response = await api("/api/session");
  currentUser = await response.json();
  if (currentUser.must_change_password) {
    location.replace("/login.html");
    return;
  }
  document.body.dataset.role = currentUser.role;
  document.getElementById("user-badge").textContent = `${currentUser.username} · ${ROLE_LABEL[currentUser.role]}`;
  loadVersion().catch(() => {});
  await loadSnapshot().catch((error) => {
    document.getElementById("capture-interface").textContent = `Server connection error: ${error.message}`;
  });
  connect();
  if (can("admin")) {
    loadAdmin();
    setInterval(loadAdmin, 15000);
  }
}
start();
