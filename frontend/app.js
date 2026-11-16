const svg = document.getElementById("topology");
const edgesLayer = document.getElementById("edges");
const nodesLayer = document.getElementById("nodes");
const assetList = document.getElementById("asset-list");
const assetDetail = document.getElementById("asset-detail");
const searchInput = document.getElementById("asset-search");
const alertsBody = document.getElementById("alerts-body");
const showAcked = document.getElementById("show-acked");
const positions = new Map();
let latestSnapshot = { assets: [], links: [], alerts: [], stats: {}, sensor: {}, import: {} };
let selectedId = null;

const SEVERITY_LABEL = { critical: "심각", high: "높음", medium: "보통", low: "낮음", info: "정보" };
const CATEGORY_LABEL = {
  read: "읽기", monitor: "모니터링", session: "세션", discovery: "탐색", diagnostic: "진단",
  write: "쓰기", command: "제어 명령", config: "설정 변경", program: "프로그램 변경",
  control: "운전 상태 제어", firmware: "펌웨어",
};

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]);
}

function nodeClass(asset) {
  const type = asset.device_type.toLowerCase();
  if (type.includes("plc")) return "node-type-plc";
  if (type.includes("rtu") || type.includes("ied") || type.includes("merging")) return "node-type-power";
  if (type.includes("workstation") || type.includes("hmi") || type.includes("scada")) return "node-type-workstation";
  if (type.includes("building")) return "node-type-building";
  if (type !== "unknown") return "node-type-industrial";
  return "node-type-unknown";
}

function shortType(asset) {
  return asset.device_type === "Unknown" ? "미확인 자산" : asset.device_type;
}

function subtitle(asset) {
  const identity = [asset.vendor, asset.model].filter(Boolean).join(" ");
  return identity || shortType(asset);
}

function formatTime(value) {
  if (!value) return "";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("ko-KR", { hour12: false });
}

function labelOf(id) {
  const asset = (latestSnapshot.assets || []).find((item) => item.id === id);
  return asset ? asset.label : id || "-";
}

function getPosition(asset, index, count) {
  if (positions.has(asset.id)) return positions.get(asset.id);
  const hash = [...asset.id].reduce((value, char) => ((value * 31) + char.charCodeAt(0)) >>> 0, 7);
  const angle = ((hash % 360) * Math.PI) / 180;
  const ring = Math.floor(index / 12);
  const radius = Math.min(215, 70 + ring * 46 + Math.min(count, 12) * 6);
  const position = { x: 480 + Math.cos(angle) * radius, y: 255 + Math.sin(angle) * radius * 0.78 };
  positions.set(asset.id, position);
  return position;
}

// Small incremental force layout: nodes repel, linked nodes attract, everything stays in the frame.
// Positions persist between renders, so the map settles instead of jumping.
function relax(assets, links, points, iterations = 40) {
  const W = 960, H = 520, PAD = 45;
  const ideal = Math.max(70, Math.min(150, 520 / Math.sqrt(assets.length || 1)));
  for (let iter = 0; iter < iterations; iter += 1) {
    const force = new Map(assets.map((a) => [a.id, { x: 0, y: 0 }]));
    for (let i = 0; i < assets.length; i += 1) {
      for (let j = i + 1; j < assets.length; j += 1) {
        const a = points.get(assets[i].id), b = points.get(assets[j].id);
        let dx = a.x - b.x, dy = a.y - b.y;
        const dist = Math.max(1, Math.hypot(dx, dy));
        if (dist === 1) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; }
        const push = (ideal * ideal) / dist / dist;
        force.get(assets[i].id).x += (dx / dist) * push; force.get(assets[i].id).y += (dy / dist) * push;
        force.get(assets[j].id).x -= (dx / dist) * push; force.get(assets[j].id).y -= (dy / dist) * push;
      }
    }
    links.forEach((link) => {
      const a = points.get(link.source), b = points.get(link.target);
      if (!a || !b || a === b) return;
      const dx = b.x - a.x, dy = b.y - a.y;
      const dist = Math.max(1, Math.hypot(dx, dy));
      const pull = (dist - ideal) / dist * 0.05;
      force.get(link.source).x += dx * pull; force.get(link.source).y += dy * pull;
      force.get(link.target).x -= dx * pull; force.get(link.target).y -= dy * pull;
    });
    assets.forEach((asset) => {
      const p = points.get(asset.id), f = force.get(asset.id);
      f.x += (W / 2 - p.x) * 0.004; f.y += (H / 2 - p.y) * 0.006;
      p.x = Math.min(W - PAD, Math.max(PAD, p.x + Math.max(-12, Math.min(12, f.x * 8))));
      p.y = Math.min(H - PAD, Math.max(PAD - 15, p.y + Math.max(-12, Math.min(12, f.y * 8))));
    });
  }
}

function searchText(asset) {
  return [asset.label, asset.ip, asset.device_type, asset.vendor, asset.model, asset.name,
    asset.firmware, ...(asset.macs || []), ...(asset.protocols || [])].join(" ").toLowerCase();
}

function render(snapshot) {
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

  // Links whose client issued risky operations are drawn as alert edges.
  const alertPairs = new Set((snapshot.alerts || []).filter((a) => a.status === "new")
    .map((a) => `${a.src}|${a.dst}`));

  const nodePositions = new Map();
  visibleAssets.forEach((asset, index) => {
    nodePositions.set(asset.id, getPosition(asset, index, visibleAssets.length));
  });
  relax(visibleAssets, visibleLinks, nodePositions);

  // One edge per asset pair; label with application protocols (transport-only labels as fallback).
  const generic = new Set(["TCP", "UDP", "ICMP", "ISO-TSAP"]);
  const edges = new Map();
  visibleLinks.forEach((link) => {
    const key = `${link.source}|${link.target}`;
    const edge = edges.get(key) || { source: link.source, target: link.target, protocols: new Set(), last: 0 };
    edge.protocols.add(link.protocol);
    edge.last = Math.max(edge.last, Date.parse(link.last_seen));
    edges.set(key, edge);
  });
  edgesLayer.innerHTML = [...edges.values()].map((edge) => {
    const from = nodePositions.get(edge.source);
    const to = nodePositions.get(edge.target);
    const stale = Date.now() - edge.last > 60000;
    const alerting = alertPairs.has(`${edge.source}|${edge.target}`);
    const specific = [...edge.protocols].filter((p) => !generic.has(p) && !p.includes("("));
    const label = (specific.length ? specific : [...edge.protocols]).join(", ");
    // Stop the line at the node halo so the arrowhead stays visible.
    const len = Math.max(1, Math.hypot(to.x - from.x, to.y - from.y));
    const ux = (to.x - from.x) / len, uy = (to.y - from.y) / len;
    const x1 = from.x + ux * 30, y1 = from.y + uy * 30, x2 = to.x - ux * 31, y2 = to.y - uy * 31;
    return `<g>
      <line class="edge-line ${stale ? "edge-stale" : ""} ${alerting ? "edge-alert" : ""}"
        x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}"></line>
      <text class="edge-label" x="${(from.x + to.x) / 2}" y="${(from.y + to.y) / 2 - 5}" text-anchor="middle">${escapeHtml(label)}</text>
    </g>`;
  }).join("");

  const alertAssets = new Set([...alertPairs].flatMap((pair) => pair.split("|")));
  nodesLayer.innerHTML = visibleAssets.map((asset) => {
    const point = nodePositions.get(asset.id);
    const classes = [
      "node", nodeClass(asset),
      asset.id === selectedId ? "node-selected" : "",
      asset.status === "stale" ? "node-offline" : "",
      alertAssets.has(asset.id) ? "node-alert" : "",
    ].join(" ");
    return `<g class="${classes}" data-id="${escapeHtml(asset.id)}" transform="translate(${point.x} ${point.y})">
      <circle class="node-halo" r="29"></circle>
      <circle class="node-core" r="20"></circle>
      <text x="0" y="4" text-anchor="middle" fill="#dce5f2" font-size="12">${asset.device_type === "Unknown" ? "?" : "◆"}</text>
      <text class="node-label" x="0" y="39">${escapeHtml(asset.label)}</text>
      <text class="node-sub" x="0" y="51">${escapeHtml(subtitle(asset).slice(0, 34))}</text>
    </g>`;
  }).join("");

  renderAssetList(visibleAssets);
  renderAssetDetail(assets.find((asset) => asset.id === selectedId));
  renderAlerts(snapshot.alerts || []);
}

function renderStatus(sensor) {
  const pill = document.getElementById("sensor-status");
  const label = sensor.error ? "센서 오류" : sensor.enabled ? "패킷 수집 중" : "실시간 수집 꺼짐";
  pill.className = `status-pill ${sensor.error ? "status-error" : sensor.enabled ? "status-online" : "status-offline"}`;
  pill.innerHTML = `<span class="status-dot"></span>${label}`;
  const interfaceLabel = sensor.interface
    ? `수집 인터페이스: ${sensor.interface}`
    : "NETEYE_INTERFACE 환경 변수로 실시간 수집 인터페이스를 설정하거나 PCAP을 분석하세요";
  document.getElementById("capture-interface").textContent = sensor.error
    ? `${interfaceLabel} · ${sensor.error}` : interfaceLabel;
  pill.title = sensor.error || "";
}

function renderImport(state) {
  const el = document.getElementById("import-status");
  if (state.running) {
    el.textContent = `${state.file} 분석 중… ${state.frames.toLocaleString()} 프레임`;
    el.className = "import-status running";
  } else if (state.error) {
    el.textContent = `분석 실패: ${state.error}`;
    el.className = "import-status error";
  } else if (state.last_result) {
    el.textContent = `${state.last_result.file}: ${state.last_result.frames.toLocaleString()} 프레임 분석 완료`;
    el.className = "import-status";
  } else {
    el.textContent = "";
  }
}

function renderAssetList(assets) {
  if (assets.length === 0) {
    assetList.innerHTML = '<div class="list-placeholder">검색 결과가 없습니다.</div>';
    return;
  }
  assetList.innerHTML = assets.map((asset) => `
    <button class="asset-row ${asset.id === selectedId ? "selected" : ""}" data-id="${escapeHtml(asset.id)}">
      <span class="asset-avatar ${nodeClass(asset)}">${asset.device_type === "Unknown" ? "?" : "◆"}</span>
      <span class="asset-row-copy">
        <strong>${escapeHtml(asset.label)}</strong>
        <span>${escapeHtml(subtitle(asset))}</span>
      </span>
      <i class="row-status ${asset.status === "stale" ? "stale" : ""}"></i>
    </button>`).join("");
}

function detailItem(label, value) {
  return value ? `<div class="detail-item"><span>${label}</span><strong>${escapeHtml(value)}</strong></div>` : "";
}

function renderAssetDetail(asset) {
  if (!asset) {
    assetDetail.innerHTML = '<div class="detail-placeholder"><span class="detail-placeholder-icon">◎</span><span>그래프 또는 목록에서 자산을 선택하세요.</span></div>';
    return;
  }
  const confidence = Math.round((asset.confidence || 0) * 100);
  const evidence = (asset.evidence || []).length
    ? `<ul class="evidence-list">${asset.evidence.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`
    : "<span>아직 식별 근거가 없습니다.</span>";
  const comms = (latestSnapshot.links || []).filter((l) => l.source === asset.id || l.target === asset.id);
  const commsHtml = comms.length ? comms.map((link) => {
    const outbound = link.source === asset.id;
    const peer = labelOf(outbound ? link.target : link.source);
    const ops = Object.entries(link.operations || {}).sort((a, b) => b[1] - a[1]).slice(0, 6)
      .map(([op, n]) => `<li>${escapeHtml(op)} <em>×${n}</em></li>`).join("");
    const cats = Object.keys(link.categories || {}).map((c) => CATEGORY_LABEL[c] || c).join(", ");
    return `<div class="comm">
      <div class="comm-head"><b>${outbound ? "→" : "←"} ${escapeHtml(peer)}</b><span>${escapeHtml(link.protocol)}</span></div>
      ${cats ? `<div class="comm-cats">${escapeHtml(cats)}</div>` : ""}
      ${ops ? `<ul class="op-list">${ops}</ul>` : ""}
    </div>`;
  }).join("") : "<span>관측된 통신이 없습니다.</span>";

  assetDetail.innerHTML = `
    <div class="selected-asset">
      <h3>${escapeHtml(asset.label)}</h3>
      <p class="asset-type">${escapeHtml(shortType(asset))}</p>
      <div class="detail-grid">
        <div class="detail-item"><span>식별 신뢰도</span><strong>${confidence}%</strong><div class="confidence-track"><i style="width:${confidence}%"></i></div></div>
        ${detailItem("벤더", asset.vendor)}
        ${detailItem("모델 / 주문번호", asset.model)}
        ${detailItem("제품 코드", asset.product_code)}
        ${detailItem("펌웨어", asset.firmware)}
        ${detailItem("시리얼", asset.serial)}
        ${detailItem("장비 이름", asset.name)}
        ${detailItem("설명", asset.description)}
        ${detailItem("MAC 주소", (asset.macs || []).join(", ") || "미확인")}
        ${detailItem("VLAN", (asset.vlans || []).join(", "))}
        ${detailItem("역할", (asset.roles || []).join(", "))}
        ${detailItem("관측 프로토콜", (asset.protocols || []).join(", "))}
        <div class="detail-item"><span>식별 근거</span>${evidence}</div>
        <div class="detail-item"><span>통신 및 명령</span>${commsHtml}</div>
        ${detailItem("패킷 / 바이트", `${asset.packets.toLocaleString()} / ${asset.bytes.toLocaleString()}`)}
        <div class="detail-item"><span>최초 / 최근 관측</span><strong>${escapeHtml(formatTime(asset.first_seen))}<br>${escapeHtml(formatTime(asset.last_seen))}</strong></div>
      </div>
    </div>`;
}

const alertSource = document.getElementById("alert-source");

function renderBaseline(baseline) {
  if (!baseline) return;
  const learning = baseline.mode === "learning";
  const bar = document.getElementById("baseline-bar");
  bar.className = `baseline-bar ${learning ? "mode-learning" : "mode-detecting"}`;
  document.getElementById("mode-badge").textContent = learning ? "학습 중" : "탐지 중";
  let title = learning ? "정상 통신 학습 중" : "베이스라인 이탈 탐지 중";
  if (learning && baseline.learning_until) {
    const left = Math.max(0, baseline.learning_until * 1000 - Date.now());
    const hours = Math.floor(left / 3600000), minutes = Math.ceil((left % 3600000) / 60000);
    title += ` · ${hours ? `${hours}시간 ` : ""}${minutes}분 후 탐지 모드로 자동 전환`;
  }
  document.getElementById("mode-title").textContent = title;
  document.getElementById("mode-desc").textContent = learning
    ? "관측되는 자산·통신·명령을 정상 베이스라인으로 기록합니다. 위험 명령 경고는 학습 중에도 발생합니다."
    : `${formatTime(new Date(baseline.mode_since * 1000).toISOString())}부터 베이스라인에 없는 자산·통신·명령을 경고합니다.`;
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
  const response = await fetch("/api/baseline/mode", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  if (!response.ok) alert(`모드 변경 실패: ${response.status}`);
  await loadSnapshot();
}

function renderAlerts(alerts) {
  const source = alertSource.value;
  const rows = alerts.filter((a) => (showAcked.checked || a.status === "new") && (!source || a.source === source));
  if (rows.length === 0) {
    alertsBody.innerHTML = `<tr><td colspan="8" class="empty-row">표시할 경고가 없습니다.</td></tr>`;
    return;
  }
  alertsBody.innerHTML = rows.slice(0, 200).map((a) => `
    <tr class="${a.status === "acknowledged" ? "acked" : ""}">
      <td><span class="sev sev-${a.severity}">${SEVERITY_LABEL[a.severity] || a.severity}</span></td>
      <td><span class="src-tag src-${a.source === "baseline" ? "baseline" : "policy"}">${a.source === "baseline" ? "이탈" : "정책"}</span></td>
      <td><strong>${escapeHtml(a.title)}</strong>${a.category_label ? `<small>${escapeHtml(a.category_label)}</small>` : ""}</td>
      <td class="mono"><a data-id="${escapeHtml(a.src)}">${escapeHtml(labelOf(a.src))}</a>${a.dst ? ` → <a data-id="${escapeHtml(a.dst)}">${escapeHtml(labelOf(a.dst))}</a>` : ""}</td>
      <td>${escapeHtml(a.protocol)}</td>
      <td class="mono">${a.count}</td>
      <td class="mono">${escapeHtml(formatTime(a.last_seen))}</td>
      <td class="actions">${a.status === "new"
        ? `${a.baseline ? `<button class="ack learn" data-learn="${a.id}" title="이 동작을 정상으로 베이스라인에 추가">정상 등록</button>` : ""}<button class="ack" data-ack="${a.id}">확인</button>`
        : "확인됨"}</td>
    </tr>`).join("");
}

document.addEventListener("click", async (event) => {
  const learn = event.target.closest("[data-learn]");
  if (learn) {
    learn.disabled = true;
    await fetch(`/api/alerts/${learn.dataset.learn}/learn`, { method: "POST" });
    await loadSnapshot();
    return;
  }
  const ack = event.target.closest("[data-ack]");
  if (ack) {
    ack.disabled = true;
    await fetch(`/api/alerts/${ack.dataset.ack}/ack`, { method: "POST" });
    await loadSnapshot();
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
document.getElementById("btn-detect").addEventListener("click", () => setMode("detecting"));
document.getElementById("btn-learn").addEventListener("click", () => setMode("learning"));
document.getElementById("btn-reset").addEventListener("click", () => {
  if (confirm("베이스라인을 모두 지우고 처음부터 다시 학습할까요? 이후 관측되는 모든 통신이 정상으로 기록됩니다.")) {
    setMode("learning", true);
  }
});

document.getElementById("pcap-input").addEventListener("change", async (event) => {
  const file = event.target.files[0];
  event.target.value = "";
  if (!file) return;
  const status = document.getElementById("import-status");
  status.textContent = `${file.name} 업로드 중…`;
  status.className = "import-status running";
  const response = await fetch("/api/pcap", {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream", "X-Filename": encodeURIComponent(file.name) },
    body: file,
  });
  if (!response.ok) {
    const detail = await response.json().catch(() => ({}));
    status.textContent = `업로드 실패: ${detail.detail || response.status}`;
    status.className = "import-status error";
  }
});

async function loadSnapshot() {
  const response = await fetch("/api/snapshot");
  if (!response.ok) throw new Error(`Snapshot request failed: ${response.status}`);
  render(await response.json());
}

function connect() {
  const scheme = location.protocol === "https:" ? "wss:" : "ws:";
  const socket = new WebSocket(`${scheme}//${location.host}/ws`);
  socket.addEventListener("message", (event) => render(JSON.parse(event.data)));
  socket.addEventListener("close", () => setTimeout(connect, 2000));
  socket.addEventListener("error", () => socket.close());
}

loadSnapshot().catch((error) => {
  document.getElementById("capture-interface").textContent = `서버 연결 오류: ${error.message}`;
});
connect();
