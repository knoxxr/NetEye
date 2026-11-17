// Network map on a <canvas>: force layout that settles and stops, zoom/pan, and live packet flow.
//
// Performance notes: the layout runs a few steps per animation frame only while it is still moving
// (alpha cooling), drawing happens only when something changed (layout, particles, hover, view), and
// nothing in the DOM is rebuilt when a snapshot arrives. Large maps switch repulsion to a grid so a
// step stays roughly linear in the number of nodes.

/* exported NetGraph */
class NetGraph {
  constructor(wrap, { onSelect } = {}) {
    this.wrap = wrap;
    this.canvas = wrap.querySelector("canvas");
    this.ctx = this.canvas.getContext("2d");
    this.tooltip = wrap.querySelector(".graph-tooltip");
    this.onSelect = onSelect || (() => {});
    this.nodes = new Map();          // id -> node
    this.nodeList = [];
    this.edges = new Map();          // "a|b" (a < b) -> edge
    this.edgeList = [];
    this.remembered = new Map();     // id -> {x, y, fixed}: positions of nodes hidden by a search
    this.counters = new Map();       // link key -> {fwd, back}
    this.particles = [];
    this.view = { k: 1, x: 0, y: 0 };
    this.userMoved = false;          // stop auto-fitting once the user zooms or pans
    this.alpha = 0;
    this.selectedId = null;
    this.alertAssets = new Set();
    this.hover = null;
    this.lastUpdate = 0;
    this.dirty = true;
    this.width = 0;
    this.height = 0;
    this.dpr = 1;
    this.pointers = new Map();
    this.drag = null;
    let stored = null;
    try { stored = localStorage.getItem("neteye.flow"); } catch { /* storage unavailable */ }
    const reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    this.flow = stored === null ? !reduced : stored === "1";
    // View options: layout mode, external addresses folded into one node, isolated assets hidden.
    let options = {};
    try { options = JSON.parse(localStorage.getItem("neteye.graph") || "{}"); } catch { /* storage unavailable */ }
    this.options = { mode: "group", collapseExternal: true, hideIsolated: false, ...options };
    this.onOptions = () => {};
    this.groupCenters = new Map();
    this.groupSignature = "";
    this.input = null;
    this.bindEvents();
    new ResizeObserver(() => this.resize()).observe(this.wrap);
    this.resize();
    this.frame = this.frame.bind(this);
    requestAnimationFrame(this.frame);
  }

  // ------------------------------------------------------------ data
  /**
   * assets: visible assets; links: visible links; alertPairs: Set of "src|dst" with open alerts.
   * `fresh` is false when the same snapshot is rendered again (selection, search), so packet
   * counters are not diffed twice.
   */
  update(assets, links, alertPairs, selectedId, fresh) {
    const now = performance.now();
    this.input = { assets, links, alertPairs };
    this.selectedId = selectedId;
    this.alertAssets = new Set([...alertPairs].flatMap((pair) => pair.split("|")));
    let structural = false;

    // Public addresses become one "internet" node unless the user expands them.
    const idMap = new Map();
    let external = null;
    if (this.options.collapseExternal) {
      const members = assets.filter((a) => NetGraph.isExternal(a.ip));
      if (members.length) {
        const protocols = new Map();
        members.forEach((a) => (a.protocols || []).forEach((p) => protocols.set(p, (protocols.get(p) || 0) + 1)));
        external = {
          id: NetGraph.EXTERNAL, label: `인터넷 · 외부 ${members.length}개`, device_type: "External", ip: null,
          vendor: "", model: "", status: members.some((a) => a.status !== "stale") ? "online" : "stale",
          packets: members.reduce((sum, a) => sum + (a.packets || 0), 0),
          protocols: [...protocols.entries()].sort((x, y) => y[1] - x[1]).map(([p]) => p),
          members: members.map((a) => a.label),
        };
        members.forEach((a) => idMap.set(a.id, NetGraph.EXTERNAL));
        assets = [...assets.filter((a) => !idMap.has(a.id)), external];
        if (external.members.length && [...alertPairs].some((pair) => pair.split("|").some((id) => idMap.has(id)))) {
          this.alertAssets.add(NetGraph.EXTERNAL);
        }
      }
    }
    const mapId = (id) => idMap.get(id) || id;
    if (this.options.hideIsolated) {
      const linked = new Set();
      links.forEach((l) => {
        const s = mapId(l.source), t = mapId(l.target);
        if (s !== t) { linked.add(s); linked.add(t); }
      });
      assets = assets.filter((a) => linked.has(a.id) || a.id === selectedId);
    }

    const keep = new Set();
    assets.forEach((asset) => {
      keep.add(asset.id);
      let node = this.nodes.get(asset.id);
      if (!node) {
        node = { id: asset.id, x: 0, y: 0, vx: 0, vy: 0, fixed: false, flash: 0, placed: false, degree: 0 };
        const saved = this.remembered.get(asset.id);
        if (saved) Object.assign(node, saved, { placed: true });
        this.nodes.set(asset.id, node);
        structural = true;
      }
      node.asset = asset;
      // A computer name reads better than an address: show it first, the address underneath.
      const named = (asset.manual && asset.manual.name) || asset.hostname;
      node.label = named || asset.label;
      node.sub = (() => {
        const identity = [asset.vendor, asset.model].filter(Boolean).join(" ");
        if (named) return [asset.label, identity || asset.os].filter(Boolean).join(" · ").slice(0, 40);
        return (identity || asset.os || (asset.device_type === "Unknown" ? "미확인 자산" : asset.device_type)).slice(0, 40);
      })();
      // Bigger circles for assets that carry more traffic (log scale, 0.8x .. 1.7x).
      node.scale = Math.min(1.7, Math.max(0.8, 0.8 + 0.16 * Math.log10(1 + (asset.packets || 0))));
      if (asset.id === NetGraph.EXTERNAL) node.sub = "외부 주소 묶음 · 클릭하면 펼침";
      node.style = NetGraph.styleOf(asset);
      node.offline = asset.status === "stale";
      node.glyph = asset.id === NetGraph.EXTERNAL ? "◎" : asset.device_type === "Unknown" ? "?" : "◆";
      node.group = NetGraph.groupOf(asset);
      node.level = NetGraph.levelOf(asset, node.style);
    });
    for (const [id, node] of this.nodes) {
      if (!keep.has(id)) {
        this.remembered.set(id, { x: node.x, y: node.y, fixed: node.fixed });
        this.nodes.delete(id);
        structural = true;
      }
    }

    // One edge per asset pair; the direction of each packet is kept for the flow animation.
    const generic = new Set(["TCP", "UDP", "ICMP", "ISO-TSAP"]);
    const nextEdges = new Map();
    const dt = Math.min(2000, Math.max(250, now - (this.lastUpdate || now)));
    const spawn = [];
    links.forEach((link) => {
      const src = mapId(link.source), dst = mapId(link.target);
      if (src === dst || !keep.has(src) || !keep.has(dst)) return;
      const a = src < dst ? src : dst;
      const b = a === src ? dst : src;
      const key = `${a}|${b}`;
      let edge = nextEdges.get(key);
      if (!edge) {
        edge = this.edges.get(key) || { key, a, b, rate: 0 };
        Object.assign(edge, { protocols: new Set(), last: 0, toB: false, toA: false, alert: false, delta: 0 });
        nextEdges.set(key, edge);
      }
      edge.protocols.add(link.protocol);
      edge.last = Math.max(edge.last, Date.parse(link.last_seen) || 0);
      if (src === a) edge.toB = true; else edge.toA = true;
      if (alertPairs.has(`${link.source}|${link.target}`) || alertPairs.has(`${link.target}|${link.source}`)) edge.alert = true;

      const back = link.packets_back || 0;
      const fwd = link.packets - back;
      const linkKey = `${link.source}|${link.target}|${link.protocol}`;
      const prev = this.counters.get(linkKey);
      if (fresh) this.counters.set(linkKey, { fwd, back });
      if (fresh && prev && this.lastUpdate) {
        const dFwd = Math.max(0, fwd - prev.fwd), dBack = Math.max(0, back - prev.back);
        edge.delta += dFwd + dBack;
        // Requests travel client -> server; replies and reports come back.
        if (dFwd) spawn.push([edge, src === a ? 1 : -1, dFwd, "req"]);
        if (dBack) spawn.push([edge, src === a ? -1 : 1, dBack, "resp"]);
      }
    });
    for (const key of this.edges.keys()) if (!nextEdges.has(key)) structural = true;
    for (const key of nextEdges.keys()) if (!this.edges.has(key)) structural = true;
    this.edges = nextEdges;

    this.nodeList = [...this.nodes.values()];
    this.nodeList.forEach((n) => { n.degree = 0; });
    this.edgeList = [];
    const nowMs = Date.now();
    for (const edge of this.edges.values()) {
      edge.na = this.nodes.get(edge.a);
      edge.nb = this.nodes.get(edge.b);
      if (!edge.na || !edge.nb) continue;
      edge.na.degree += 1;
      edge.nb.degree += 1;
      const specific = [...edge.protocols].filter((p) => !generic.has(p) && !p.includes("("));
      edge.label = (specific.length ? specific : [...edge.protocols]).join(", ");
      edge.stale = nowMs - edge.last > 60000;
      edge.cross = edge.na.group.key !== edge.nb.group.key;
      if (fresh && this.lastUpdate) edge.rate = edge.delta / (dt / 1000);
      this.edgeList.push(edge);
    }

    this.layoutGroups();
    this.placeNewNodes();
    if (fresh) {
      if (this.lastUpdate && this.flow) this.spawn(spawn, dt, now);
      this.lastUpdate = now;
    }
    if (structural) {
      this.alpha = Math.max(this.alpha, this.nodeList.some((n) => !n.settled) ? 1 : 0.3);
    }
    this.dirty = true;
  }

  /** Re-run the last update with the current options (no packet diffing). */
  refresh() {
    if (this.input) this.update(this.input.assets, this.input.links, this.input.alertPairs, this.selectedId, false);
  }

  setOption(name, value) {
    if (this.options[name] === value) return;
    this.options[name] = value;
    try { localStorage.setItem("neteye.graph", JSON.stringify(this.options)); } catch { /* storage unavailable */ }
    if (name === "mode") this.nodeList.forEach((n) => { n.fixed = false; });
    this.refresh();
    this.alpha = 1;
    this.userMoved = false;
    this.onOptions(this.options);
  }

  static isExternal(ip) {
    const m = /^(\d+)\.(\d+)\.\d+\.\d+$/.exec(ip || "");
    if (!m) return false;
    const a = Number(m[1]), b = Number(m[2]);
    return !(a === 10 || a === 127 || a === 0 || a >= 224 || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127));
  }

  /** Subnet group: private /24, everything public, or layer-2 devices without an address. */
  static groupOf(asset) {
    if (asset.id === NetGraph.EXTERNAL || NetGraph.isExternal(asset.ip)) return { key: "~ext", label: "외부망 · 인터넷" };
    const m = /^(\d+\.\d+\.\d+)\.\d+$/.exec(asset.ip || "");
    if (m) return { key: `${m[1]}.0/24`, label: `${m[1]}.0/24` };
    return asset.ip ? { key: "~other", label: "기타 주소" } : { key: "~l2", label: "L2 장비 (IP 없음)" };
  }

  /** Purdue level: 1 controllers and field devices, 2 supervisory, 3 site/IT, 4 external. */
  static levelOf(asset, style) {
    if (asset.id === NetGraph.EXTERNAL || NetGraph.isExternal(asset.ip)) return 4;
    if (style === NetGraph.STYLES.workstation) return 2;
    if (style === NetGraph.STYLES.unknown) return 3;
    return 1;
  }

  /**
   * Each subnet gets its own area. Inside it, assets that talk are laid out by force at the top;
   * assets seen only through ARP/broadcasts sit in a tidy grid below, in address order. Areas are
   * shelf-packed by height, the external area first so links to it do not cross the grids.
   */
  layoutGroups() {
    const members = new Map();
    for (const n of this.nodes.values()) {
      const g = members.get(n.group.key) || { label: n.group.label, linked: 0, idle: [] };
      if (n.degree) g.linked += 1; else g.idle.push(n);
      members.set(n.group.key, g);
    }
    const signature = [...members].map(([k, g]) => `${k}:${g.linked}:${g.idle.length}`).sort().join(",");
    if (signature === this.groupSignature) return;
    this.groupSignature = signature;
    for (const n of this.nodes.values()) n.slot = null;
    const CELL_X = 92, CELL_Y = 84;
    const groups = [...members].map(([key, g]) => {
      const rc = g.linked ? 60 + 52 * Math.sqrt(g.linked) : 0;
      const cols = g.idle.length ? Math.ceil(Math.sqrt(g.idle.length * 2.2)) : 0;
      const rows = cols ? Math.ceil(g.idle.length / cols) : 0;
      const w = Math.max(2 * rc, cols * CELL_X, 160);
      const h = 2 * rc + rows * CELL_Y + (rc && rows ? 20 : 0);
      return { key, ...g, rc, cols, rows, w, h: Math.max(h, 140) };
    }).sort((x, y) => (y.key === "~ext") - (x.key === "~ext") || y.h - x.h); // external first: its links stay short
    const gap = 120;
    const rowLimit = Math.max(groups[0] ? groups[0].w : 0,
      Math.sqrt(groups.reduce((sum, g) => sum + (g.w + gap) * (g.h + gap), 0)) * 1.4);
    let x = 0, y = 0, rowHeight = 0, width = 0;
    const centers = new Map();
    for (const g of groups) {
      if (x > 0 && x + g.w > rowLimit) { x = 0; y += rowHeight + gap; rowHeight = 0; }
      centers.set(g.key, { left: x, top: y, w: g.w, h: g.h, g });
      x += g.w + gap;
      rowHeight = Math.max(rowHeight, g.h);
      width = Math.max(width, x - gap);
    }
    const height = y + rowHeight;
    const ipOrder = (n) => (n.asset.ip || n.id).split(/[.:]/).map((p) => p.padStart(3, "0")).join(".");
    for (const c of centers.values()) {
      c.left -= width / 2;
      c.top -= height / 2;
      const g = c.g;
      // Force-laid part: centre of the top block.
      c.x = c.left + c.w / 2;
      c.y = g.linked ? c.top + g.rc : c.top + c.h / 2;
      g.idle.sort((p, q) => (ipOrder(p) < ipOrder(q) ? -1 : 1));
      const gridTop = c.top + 2 * g.rc + (g.rc ? 20 : 0) + CELL_Y / 2;
      const gridLeft = c.x - (g.cols * CELL_X) / 2 + CELL_X / 2;
      g.idle.forEach((n, i) => {
        n.slot = { x: gridLeft + (i % g.cols) * CELL_X, y: gridTop + Math.floor(i / g.cols) * CELL_Y };
      });
    }
    this.groupCenters = centers;
    if (this.options.mode === "group") {
      for (const n of this.nodes.values()) {
        if (n.slot && !n.placed) { n.x = n.slot.x; n.y = n.slot.y; n.placed = true; }
        if (!n.placed) {
          const c = centers.get(n.group.key);
          const angle = Math.random() * Math.PI * 2, r = (c.g.rc || 60) * 0.6 * Math.sqrt(Math.random());
          n.x = c.x + Math.cos(angle) * r;
          n.y = c.y + Math.sin(angle) * r;
          n.placed = true;
        }
      }
      this.alpha = Math.max(this.alpha, 0.6);
    }
  }

  static styleOf(asset) {
    if (asset.id === NetGraph.EXTERNAL) return NetGraph.STYLES.external;
    const type = asset.device_type.toLowerCase();
    if (type.includes("plc")) return NetGraph.STYLES.plc;
    if (type.includes("rtu") || type.includes("ied") || type.includes("merging")) return NetGraph.STYLES.power;
    if (type.includes("workstation") || type.includes("hmi") || type.includes("scada")) return NetGraph.STYLES.workstation;
    if (type.includes("building")) return NetGraph.STYLES.building;
    if (type !== "unknown") return NetGraph.STYLES.industrial;
    return NetGraph.STYLES.unknown;
  }

  /** New nodes start next to an already placed neighbour, so the map grows instead of reshuffling. */
  placeNewNodes() {
    const pending = this.nodeList.filter((n) => !n.placed);
    if (!pending.length) return;
    const spread = 60 * Math.sqrt(this.nodeList.length + 1);
    for (let pass = 0; pass < 2; pass += 1) {
      for (const edge of this.edgeList) {
        const [p, q] = edge.na.placed ? [edge.na, edge.nb] : [edge.nb, edge.na];
        if (p.placed && !q.placed) {
          const angle = Math.random() * Math.PI * 2;
          q.x = p.x + Math.cos(angle) * 90;
          q.y = p.y + Math.sin(angle) * 90;
          q.placed = true;
        }
      }
    }
    pending.forEach((n) => {
      if (n.placed) return;
      const angle = Math.random() * Math.PI * 2, r = spread * Math.sqrt(Math.random());
      n.x = Math.cos(angle) * r;
      n.y = Math.sin(angle) * r * 0.7;
      n.placed = true;
    });
  }

  spawn(items, dt, now) {
    const budget = NetGraph.MAX_PARTICLES - this.particles.length;
    if (budget <= 0) return;
    // A dot stands for one or more packets: busy links show more dots, but never a flood.
    const wanted = items.map(([, , n]) => Math.min(12, Math.max(1, Math.round(Math.log2(n + 1) * 2))));
    const total = wanted.reduce((s, n) => s + n, 0);
    const scale = total > budget ? budget / total : 1;
    items.forEach(([edge, dir, , kind], i) => {
      const count = Math.max(1, Math.floor(wanted[i] * scale));
      for (let j = 0; j < count; j += 1) {
        this.particles.push({ edge, dir, kind, start: now + (dt * (j + Math.random() * 0.8)) / count, dur: 0 });
      }
    });
  }

  // ------------------------------------------------------------ layout
  step() {
    const nodes = this.nodeList;
    const n = nodes.length;
    if (!n) { this.alpha = 0; return; }
    const ideal = 110;
    const alpha = this.alpha;
    const repulse = ideal * ideal * 0.9;
    for (const node of nodes) { node.fx = 0; node.fy = 0; }
    const slotted = this.options.mode === "group";
    const pair = (p, q) => {
      if (slotted && (p.slot || q.slot)) return;
      let dx = p.x - q.x, dy = p.y - q.y;
      let d2 = dx * dx + dy * dy;
      if (d2 < 1) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; d2 = 1; }
      if (d2 > 640000) return; // beyond ~800 px the push is negligible
      const f = repulse / d2;
      const d = Math.sqrt(d2);
      const fx = (dx / d) * f, fy = (dy / d) * f;
      p.fx += fx; p.fy += fy; q.fx -= fx; q.fy -= fy;
    };
    if (n <= 500) {
      for (let i = 0; i < n; i += 1) for (let j = i + 1; j < n; j += 1) pair(nodes[i], nodes[j]);
    } else {
      // Grid binning: only nearby nodes push each other. Each neighbouring cell pair is visited
      // once (same cell, then the four "forward" neighbours).
      const cell = ideal * 3, grid = new Map();
      const keyOf = (cx, cy) => (cx + 32768) * 65536 + (cy + 32768);
      for (const node of nodes) {
        const key = keyOf(Math.floor(node.x / cell), Math.floor(node.y / cell));
        const bucket = grid.get(key);
        if (bucket) bucket.push(node); else grid.set(key, [node]);
      }
      const forward = [[1, -1], [1, 0], [1, 1], [0, 1]];
      for (const [key, bucket] of grid) {
        const cx = Math.floor(key / 65536) - 32768, cy = (key % 65536) - 32768;
        for (let i = 0; i < bucket.length; i += 1) for (let j = i + 1; j < bucket.length; j += 1) pair(bucket[i], bucket[j]);
        for (const [ox, oy] of forward) {
          const other = grid.get(keyOf(cx + ox, cy + oy));
          if (!other) continue;
          for (const p of bucket) for (const q of other) pair(p, q);
        }
      }
    }
    const mode = this.options.mode;
    for (const edge of this.edgeList) {
      const p = edge.na, q = edge.nb;
      const dx = q.x - p.x, dy = q.y - p.y;
      const d = Math.max(1, Math.hypot(dx, dy));
      // Links between areas or layers barely pull, so they cannot drag nodes out of their area.
      const loose = (mode === "group" && edge.cross) || (mode === "purdue" && p.level !== q.level);
      // (in group mode not at all: dozens of external links would otherwise drag a hub out of its subnet)
      const pull = ((d - ideal) / d) * (loose ? (mode === "group" ? 0 : 0.004) : 0.06);
      p.fx += dx * pull; p.fy += dy * pull; q.fx -= dx * pull; q.fy -= dy * pull;
    }
    let moving = 0;
    for (const node of nodes) {
      if (mode === "group") {
        // Pull towards the subnet's area.
        if (node.slot) {
          node.fx += (node.slot.x - node.x) * 0.25;
          node.fy += (node.slot.y - node.y) * 0.25;
        } else {
          const c = this.groupCenters.get(node.group.key);
          if (c) { node.fx += (c.x - node.x) * 0.03; node.fy += (c.y - node.y) * 0.03; }
        }
      } else if (mode === "purdue") {
        // Hold each node in its level band; spread sideways freely.
        node.fx -= node.x * 0.003 * (node.degree ? 1 : 2);
        node.fy += (NetGraph.LEVEL_Y[node.level] - node.y) * 0.08;
      } else {
        // Weak gravity keeps disconnected islands on screen.
        node.fx -= node.x * 0.004 * (node.degree ? 1 : 3);
        node.fy -= node.y * 0.006 * (node.degree ? 1 : 3);
      }
      if (node.fixed || (this.drag && this.drag.node === node)) { node.vx = 0; node.vy = 0; continue; }
      node.vx = (node.vx + node.fx * alpha) * 0.55;
      node.vy = (node.vy + node.fy * alpha) * 0.55;
      const v = Math.hypot(node.vx, node.vy);
      if (v > 25) { node.vx *= 25 / v; node.vy *= 25 / v; }
      node.x += node.vx;
      node.y += node.vy;
      moving = Math.max(moving, v);
      node.settled = true;
    }
    this.alpha *= 0.985;
    if (this.alpha < 0.02 || (moving < 0.05 && this.alpha < 0.3)) this.alpha = 0;
  }

  // ------------------------------------------------------------ view
  resize() {
    const rect = this.canvas.getBoundingClientRect();
    this.dpr = window.devicePixelRatio || 1;
    this.width = rect.width;
    this.height = rect.height;
    this.canvas.width = Math.round(rect.width * this.dpr);
    this.canvas.height = Math.round(rect.height * this.dpr);
    if (!this.userMoved) this.fit(false);
    this.dirty = true;
  }

  bounds() {
    let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    for (const n of this.nodeList) {
      x0 = Math.min(x0, n.x); y0 = Math.min(y0, n.y); x1 = Math.max(x1, n.x); y1 = Math.max(y1, n.y);
    }
    const pad = this.options.mode === "group" && this.groupCenters.size > 1 ? 30 : 0;
    return x0 === Infinity ? null : { x0: x0 - 55 - pad, y0: y0 - 70 - pad, x1: x1 + 55 + pad, y1: y1 + 70 + pad };
  }

  fit(user = true) {
    const b = this.bounds();
    if (!b || !this.width) return;
    const k = Math.min(2, Math.max(NetGraph.MIN_ZOOM,
      Math.min(this.width / (b.x1 - b.x0), this.height / (b.y1 - b.y0))));
    this.view = { k, x: this.width / 2 - ((b.x0 + b.x1) / 2) * k, y: this.height / 2 - ((b.y0 + b.y1) / 2) * k };
    if (user) this.userMoved = false;
    this.dirty = true;
  }

  zoomAt(factor, sx, sy) {
    const k = Math.min(NetGraph.MAX_ZOOM, Math.max(NetGraph.MIN_ZOOM, this.view.k * factor));
    const wx = (sx - this.view.x) / this.view.k, wy = (sy - this.view.y) / this.view.k;
    this.view = { k, x: sx - wx * k, y: sy - wy * k };
    this.userMoved = true;
    this.dirty = true;
  }

  zoomBy(factor) { this.zoomAt(factor, this.width / 2, this.height / 2); }

  setFlow(on) {
    this.flow = on;
    if (!on) this.particles = [];
    try { localStorage.setItem("neteye.flow", on ? "1" : "0"); } catch { /* storage unavailable */ }
    this.dirty = true;
  }

  toWorld(sx, sy) { return { x: (sx - this.view.x) / this.view.k, y: (sy - this.view.y) / this.view.k }; }

  nodeAt(sx, sy) {
    const p = this.toWorld(sx, sy);
    let best = null, bestD = Infinity;
    for (const n of this.nodeList) {
      const d = (n.x - p.x) ** 2 + (n.y - p.y) ** 2;
      if (d < (26 * n.scale) ** 2 && d < bestD) { best = n; bestD = d; }
    }
    return best;
  }

  bindEvents() {
    const c = this.canvas;
    const local = (e) => { const r = c.getBoundingClientRect(); return { x: e.clientX - r.left, y: e.clientY - r.top }; };
    c.addEventListener("wheel", (e) => {
      e.preventDefault();
      const p = local(e);
      this.zoomAt(Math.exp(-e.deltaY * (e.deltaMode === 1 ? 0.04 : 0.0012)), p.x, p.y);
    }, { passive: false });
    c.addEventListener("pointerdown", (e) => {
      const p = local(e);
      c.setPointerCapture(e.pointerId);
      this.pointers.set(e.pointerId, p);
      if (this.pointers.size === 2) {
        const [a, b] = [...this.pointers.values()];
        this.drag = { pinch: Math.hypot(a.x - b.x, a.y - b.y), moved: true };
        return;
      }
      const node = this.nodeAt(p.x, p.y);
      this.drag = { node, start: p, last: p, moved: false };
      this.hideTooltip();
    });
    c.addEventListener("pointermove", (e) => {
      const p = local(e);
      if (this.pointers.has(e.pointerId)) this.pointers.set(e.pointerId, p);
      const drag = this.drag;
      if (!drag) { this.hoverAt(p); return; }
      if (drag.pinch && this.pointers.size === 2) {
        const [a, b] = [...this.pointers.values()];
        const d = Math.hypot(a.x - b.x, a.y - b.y);
        this.zoomAt(d / drag.pinch, (a.x + b.x) / 2, (a.y + b.y) / 2);
        drag.pinch = d;
        return;
      }
      if (!drag.moved && Math.hypot(p.x - drag.start.x, p.y - drag.start.y) < 4) return;
      drag.moved = true;
      if (drag.node) {
        const w = this.toWorld(p.x, p.y);
        drag.node.x = w.x; drag.node.y = w.y; drag.node.fixed = true;
        this.alpha = Math.max(this.alpha, 0.25);
      } else {
        this.view.x += p.x - drag.last.x;
        this.view.y += p.y - drag.last.y;
        this.userMoved = true;
      }
      drag.last = p;
      this.dirty = true;
    });
    const end = (e) => {
      this.pointers.delete(e.pointerId);
      const drag = this.drag;
      if (this.pointers.size > 0) return;
      this.drag = null;
      if (drag && !drag.moved && drag.node) {
        if (drag.node.id === NetGraph.EXTERNAL) this.setOption("collapseExternal", false);
        else this.onSelect(drag.node.id);
      }
    };
    c.addEventListener("pointerup", end);
    c.addEventListener("pointercancel", end);
    c.addEventListener("pointerleave", () => { if (!this.drag) this.hideTooltip(); });
    c.addEventListener("dblclick", (e) => {
      const p = local(e);
      const node = this.nodeAt(p.x, p.y);
      if (node) { node.fixed = false; this.alpha = Math.max(this.alpha, 0.3); } else this.fit();
    });
  }

  hoverAt(p) {
    const node = this.nodeAt(p.x, p.y);
    this.canvas.style.cursor = node ? "pointer" : "grab";
    if (node === this.hover) { if (node) this.placeTooltip(p); return; }
    this.hover = node;
    this.dirty = true;
    if (!node) { this.hideTooltip(); return; }
    let out = 0, inn = 0, peers = 0;
    for (const edge of this.edgeList) {
      if (edge.na !== node && edge.nb !== node) continue;
      peers += 1;
      if (edge.rate) { if (edge.na === node) out += edge.rate; else inn += edge.rate; }
    }
    const a = node.asset;
    const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]);
    const rate = out + inn;
    if (node.id === NetGraph.EXTERNAL) {
      const list = a.members.slice(0, 6).join(", ") + (a.members.length > 6 ? ` 외 ${a.members.length - 6}개` : "");
      this.tooltip.innerHTML = `<strong>${esc(node.label)}</strong><span class="mono">${esc(list)}</span>
        <span>통신 ${peers}건${rate ? ` · 최근 ${rate < 10 ? rate.toFixed(1) : Math.round(rate).toLocaleString()} pkt/s` : ""}</span>
        <span>클릭하면 외부 주소를 하나씩 펼칩니다</span>`;
      this.tooltip.hidden = false;
      this.placeTooltip(p);
      return;
    }
    this.tooltip.innerHTML = `<strong>${esc(node.label)}</strong><span>${esc(node.sub)}</span>
      <span>통신 상대 ${peers}개${rate ? ` · 최근 ${rate < 10 ? rate.toFixed(1) : Math.round(rate).toLocaleString()} pkt/s` : ""}</span>
      ${node.label !== a.label ? `<span class="mono">${esc(a.label)}</span>` : ""}
      ${a.manual && a.manual.location ? `<span>위치: <b>${esc(a.manual.location)}</b></span>` : ""}
      ${a.manual && a.manual.owner ? `<span>담당자: <b>${esc(a.manual.owner)}</b></span>` : ""}
      ${a.hostname ? `<span>컴퓨터 이름: <b>${esc(a.hostname)}</b></span>` : ""}
      ${a.os ? `<span>운영체제: <b>${esc(a.os)}</b> (추정 ${Math.round(a.os_confidence * 100)}%)</span>` : ""}
      <span>누적 ${(a.packets || 0).toLocaleString()} 패킷</span>
      ${(a.protocols || []).length ? `<span class="mono">${esc(a.protocols.slice(0, 5).join(", "))}</span>` : ""}`;
    this.tooltip.hidden = false;
    this.placeTooltip(p);
  }

  placeTooltip(p) {
    const w = this.tooltip.offsetWidth, h = this.tooltip.offsetHeight;
    this.tooltip.style.left = `${Math.min(this.width - w - 6, p.x + 14)}px`;
    this.tooltip.style.top = `${p.y + 16 + h > this.height ? p.y - h - 10 : p.y + 16}px`;
  }

  hideTooltip() { this.tooltip.hidden = true; this.hover = null; }

  // ------------------------------------------------------------ drawing
  frame(time) {
    requestAnimationFrame(this.frame);
    if (document.hidden || !this.width) return;
    if (this.alpha > 0) {
      const steps = this.nodeList.length > 800 ? 1 : 2;
      for (let i = 0; i < steps && this.alpha > 0; i += 1) this.step();
      if (!this.userMoved) this.fit(false);
      this.dirty = true;
    }
    if (this.particles.length || this.flashing) this.dirty = true;
    // The server sends nothing while the network is quiet: let link activity fade out then.
    if (this.lastUpdate && time - this.lastUpdate > 2500 && this.edgeList.some((e) => e.rate)) {
      this.edgeList.forEach((e) => { e.rate = 0; });
      this.dirty = true;
    }
    if (!this.dirty) return;
    this.dirty = false;
    this.draw(time);
  }

  draw(now) {
    const { ctx, view: { k, x: tx, y: ty }, dpr } = this;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, this.width, this.height);
    ctx.setTransform(dpr * k, 0, 0, dpr * k, dpr * tx, dpr * ty);
    // Visible world rectangle, for culling.
    const vx0 = -tx / k - 60, vy0 = -ty / k - 60, vx1 = (this.width - tx) / k + 60, vy1 = (this.height - ty) / k + 80;
    const visible = (n) => n.x > vx0 && n.x < vx1 && n.y > vy0 && n.y < vy1;
    const sel = this.selectedId;
    const focus = sel ? this.nodes.get(sel) : null;
    const px = 1 / k; // one screen pixel in world units
    const C = NetGraph.C;

    // Everything of one look goes into a single path and is painted with one call: a canvas
    // spends its time per draw call, not per shape.
    const batches = new Map();
    const path = (key, look) => {
      let b = batches.get(key);
      if (!b) { b = { ...look, path: new Path2D() }; batches.set(key, b); }
      return b.path;
    };
    const flush = () => {
      for (const b of batches.values()) {
        ctx.globalAlpha = b.alpha;
        if (b.fill) { ctx.fillStyle = b.fill; ctx.fill(b.path); }
        if (b.stroke) {
          ctx.strokeStyle = b.stroke;
          ctx.lineWidth = b.width;
          ctx.setLineDash(b.dash ? [4 * b.width, 5 * b.width] : []);
          ctx.stroke(b.path);
        }
      }
      batches.clear();
      ctx.setLineDash([]);
      ctx.globalAlpha = 1;
    };
    const unit = Math.max(px, 0.5); // line widths stay constant on screen until zoomed in past 2x

    const neighbours = new Set();
    if (focus) {
      for (const e of this.edgeList) {
        if (e.na === focus) neighbours.add(e.nb);
        else if (e.nb === focus) neighbours.add(e.na);
      }
    }

    this.drawAreas(ctx, k, px, vx0, vx1);

    // Edges and arrowheads (heads are skipped while they would be under 3 px)
    const heads = k * 7 >= 3;
    for (const e of this.edgeList) {
      const a = e.na, b = e.nb;
      if (!visible(a) && !visible(b)) continue;
      const related = !focus || a === focus || b === focus;
      const active = e.rate > 0;
      const dashed = e.stale && !active;
      const alpha = (dashed ? 0.25 : e.alert ? 0.95 : active ? 0.85 : 0.6) * (related ? 1 : 0.25)
        * (e.cross && !e.alert && !(focus && related) ? 0.6 : 1);
      const tier = NetGraph.tier(e.rate);
      const color = e.alert ? C.red : active ? NetGraph.HEAT[tier] : C.edge;
      const weight = e.alert ? 2 : active ? 1.2 + tier * 0.9 : 1.2;
      const look = `${color}|${alpha}`;
      const line = path(`L${look}|${weight}|${dashed}`, { stroke: color, alpha, width: weight * unit, dash: dashed });
      const dx = b.x - a.x, dy = b.y - a.y, len = Math.max(1, Math.hypot(dx, dy));
      const ux = dx / len, uy = dy / len;
      const ra = 30 * a.scale, rb = 30 * b.scale;
      line.moveTo(a.x + ux * ra, a.y + uy * ra);
      line.lineTo(b.x - ux * rb, b.y - uy * rb);
      if (!heads) continue;
      const tips = path(`H${look}`, { fill: color, alpha });
      if (e.toB) NetGraph.arrow(tips, b.x - ux * rb, b.y - uy * rb, ux, uy);
      if (e.toA) NetGraph.arrow(tips, a.x + ux * ra, a.y + uy * ra, -ux, -uy);
    }
    flush();
    // Protocol labels: for the selected asset's links, or everywhere once zoomed in.
    if (focus || (k > 1.1 && this.edgeList.length < 400)) {
      ctx.font = "9px Consolas, 'Courier New', monospace";
      ctx.textAlign = "center";
      ctx.fillStyle = C.edgeLabel;
      for (const e of this.edgeList) {
        if (!e.label || (!visible(e.na) && !visible(e.nb))) continue;
        if (focus && e.na !== focus && e.nb !== focus) continue;
        ctx.fillText(e.label, (e.na.x + e.nb.x) / 2, (e.na.y + e.nb.y) / 2 - 5);
      }
    }

    // Packets in flight: one pre-rendered dot image per colour, stamped with drawImage.
    if (this.particles.length) {
      const alive = [];
      const base = Math.max(1, k); // dots grow once zoomed in past 1x
      const groups = new Map();
      for (const p of this.particles) {
        if (now < p.start) { alive.push(p); continue; }
        const e = p.edge;
        const from = p.dir > 0 ? e.na : e.nb, to = p.dir > 0 ? e.nb : e.na;
        if (!this.nodes.has(from.id) || !this.nodes.has(to.id)) continue;
        if (!p.dur) {
          const tier = NetGraph.tier(e.rate);
          p.size = 1.8 + tier * 0.4;
          p.dur = Math.min(1600, Math.max(300, Math.hypot(to.x - from.x, to.y - from.y) * (4.5 - tier * 0.6)));
        }
        const t = (now - p.start) / p.dur;
        if (t >= 1) { to.flash = now; continue; }
        alive.push(p);
        const x = from.x + (to.x - from.x) * t, y = from.y + (to.y - from.y) * t;
        if (x < vx0 || x > vx1 || y < vy0 || y > vy1) continue;
        const color = e.alert ? C.red : p.kind === "req" ? C.req : C.resp;
        const dim = focus && from !== focus && to !== focus;
        const key = `${color}|${dim ? 1 : 0}|${p.size}`;
        let g = groups.get(key);
        if (!g) { g = { color, alpha: dim ? 0.3 : 1, size: p.size, xs: [] }; groups.set(key, g); }
        g.xs.push(x, y);
      }
      for (const g of groups.values()) {
        const rs = g.size * base;    // dot radius in screen pixels
        const half = (rs * 2.4) / k; // half the sprite (glow included) in world units
        const img = this.dotSprite(g.color, rs * dpr);
        ctx.globalAlpha = g.alpha;
        for (let i = 0; i < g.xs.length; i += 2) ctx.drawImage(img, g.xs[i] - half, g.xs[i + 1] - half, half * 2, half * 2);
      }
      ctx.globalAlpha = 1;
      this.particles = alive;
    }

    // Nodes: one sprite per (type, state) at the current zoom, stamped with drawImage.
    const showText = k * 10 >= 5.5;
    this.flashing = false;
    const drawn = [];
    const pulses = [];
    let lastAlpha = 1;
    for (const n of this.nodeList) {
      if (!visible(n)) continue;
      drawn.push(n);
      const alpha = (n.offline ? 0.48 : 1) * (focus && n !== focus && !neighbours.has(n) ? 0.35 : 1);
      const state = this.alertAssets.has(n.id) ? "alert" : n.id === sel ? "sel" : "";
      const s = n.scale;
      const img = this.nodeSprite(n.style, state, n.glyph, NetGraph.quantize(k * dpr * s), showText);
      if (alpha !== lastAlpha) { ctx.globalAlpha = alpha; lastAlpha = alpha; }
      ctx.drawImage(img, n.x - 32 * s, n.y - 32 * s, 64 * s, 64 * s);
      const since = now - (n.flash || 0);
      if (since < 450) pulses.push([n, since, alpha]);
    }
    ctx.globalAlpha = 1;
    // Receive pulse: a ring that grows and fades when a packet arrives.
    if (pulses.length) {
      this.flashing = true;
      ctx.lineWidth = 2 * px;
      for (const [n, since, alpha] of pulses) {
        ctx.globalAlpha = alpha * (1 - since / 450);
        ctx.strokeStyle = n.style.stroke;
        ctx.beginPath();
        ctx.arc(n.x, n.y, 29 * n.scale + since / 30, 0, Math.PI * 2);
        ctx.stroke();
      }
      ctx.globalAlpha = 1;
    }
    if (showText) {
      ctx.textAlign = "center";
      ctx.fillStyle = "#dce5f2";
      ctx.font = "10px Consolas, 'Courier New', monospace";
      for (const n of drawn) ctx.fillText(n.label, n.x, n.y + 19 + 20 * n.scale);
      if (k > 0.8) {
        ctx.fillStyle = "#8494a9";
        ctx.font = "8px 'Segoe UI', 'Malgun Gothic', sans-serif";
        for (const n of drawn) ctx.fillText(n.sub, n.x, n.y + 31 + 20 * n.scale);
      }
    }
  }

  /** Zoom levels share sprites in steps of 25 %, so zooming does not redraw them every frame. */
  static quantize(scale) {
    return Math.min(10, Math.max(0.05, 1.25 ** Math.round(Math.log(scale) / Math.log(1.25))));
  }

  sprites() {
    if (!this.spriteCache || this.spriteCache.size > 400) this.spriteCache = new Map();
    return this.spriteCache;
  }

  /** A node drawn once into a 64x64 world-unit image at `scale` pixels per unit. */
  nodeSprite(style, state, symbol, scale, glyph) {
    const key = `n|${style.stroke}|${state}|${symbol}|${scale}|${glyph}`;
    const cache = this.sprites();
    let img = cache.get(key);
    if (img) return img;
    const size = Math.max(2, Math.ceil(64 * scale));
    img = document.createElement("canvas");
    img.width = img.height = size;
    const c = img.getContext("2d");
    c.scale(size / 64, size / 64);
    c.translate(32, 32);
    const onePx = 1 / scale; // one device pixel in world units
    if (size >= 8) {
      c.beginPath();
      c.arc(0, 0, 29, 0, Math.PI * 2);
      c.fillStyle = state === "alert" ? "rgba(255,107,107,.12)" : state === "sel" ? "rgba(69,214,203,.14)" : "rgba(69,214,203,.05)";
      c.fill();
      c.lineWidth = (state === "alert" ? 1.5 : 1) * Math.max(onePx, 0.6);
      c.strokeStyle = state === "alert" ? NetGraph.C.red : state === "sel" ? NetGraph.C.cyan : "rgba(69,214,203,.13)";
      c.stroke();
    }
    c.beginPath();
    c.arc(0, 0, 20, 0, Math.PI * 2);
    c.fillStyle = style.fill;
    c.fill();
    c.lineWidth = 1.4 * Math.max(onePx, 0.6);
    c.strokeStyle = style.stroke;
    c.stroke();
    if (glyph) {
      c.fillStyle = "#dce5f2";
      c.font = "12px 'Segoe UI', sans-serif";
      c.textAlign = "center";
      c.fillText(symbol, 0, 4);
    }
    cache.set(key, img);
    return img;
  }

  /** A packet dot with its glow, `radius` device pixels across the core. */
  dotSprite(color, radius) {
    const r = Math.max(1, Math.round(radius * 2) / 2);
    const key = `d|${color}|${r}`;
    const cache = this.sprites();
    let img = cache.get(key);
    if (img) return img;
    const size = Math.ceil(r * 4.8);
    img = document.createElement("canvas");
    img.width = img.height = size;
    const c = img.getContext("2d");
    c.fillStyle = color;
    c.globalAlpha = 0.25;
    c.beginPath(); c.arc(size / 2, size / 2, r * 2.2, 0, Math.PI * 2); c.fill();
    c.globalAlpha = 1;
    c.beginPath(); c.arc(size / 2, size / 2, r, 0, Math.PI * 2); c.fill();
    cache.set(key, img);
    return img;
  }

  /** Subnet areas (group mode) or Purdue level bands (purdue mode), behind everything else. */
  drawAreas(ctx, k, px, vx0, vx1) {
    const mode = this.options.mode;
    if (mode === "group" && this.groupCenters.size > 1) {
      const boxes = new Map();
      for (const n of this.nodeList) {
        const b = boxes.get(n.group.key);
        if (b) {
          b.x0 = Math.min(b.x0, n.x); b.y0 = Math.min(b.y0, n.y); b.x1 = Math.max(b.x1, n.x); b.y1 = Math.max(b.y1, n.y);
          b.n += 1; b.s = Math.max(b.s, n.scale);
        } else boxes.set(n.group.key, { x0: n.x, y0: n.y, x1: n.x, y1: n.y, n: 1, s: n.scale, label: n.group.label });
      }
      ctx.lineWidth = px;
      ctx.font = "600 13px 'Segoe UI', 'Malgun Gothic', sans-serif";
      ctx.textAlign = "left";
      for (const [key, b] of boxes) {
        // Room for the largest node in the area and, above it, the area title.
        const padX = 40 * b.s + 8, padTop = 34 * b.s + 34, padBottom = 34 * b.s + 30;
        const title = key === "~ext" ? b.label : `${b.label} · ${b.n}대`;
        const span = b.x1 - b.x0 + 2 * padX, w = Math.max(span, ctx.measureText(title).width + 28);
        const x = b.x0 - padX - (w - span) / 2, y = b.y0 - padTop, h = b.y1 - b.y0 + padTop + padBottom;
        ctx.globalAlpha = 1;
        ctx.fillStyle = key === "~ext" ? "rgba(169,156,255,.045)" : "rgba(112,167,255,.045)";
        ctx.strokeStyle = key === "~ext" ? "rgba(169,156,255,.28)" : "rgba(112,167,255,.25)";
        ctx.beginPath();
        if (ctx.roundRect) ctx.roundRect(x, y, w, h, 18); else ctx.rect(x, y, w, h);
        ctx.fill();
        ctx.stroke();
        if (k * 13 >= 6) {
          ctx.fillStyle = key === "~ext" ? "#a99cff" : "#8fb4ff";
          ctx.fillText(title, x + 14, y + 22);
        }
      }
    } else if (mode === "purdue") {
      const levels = new Set(this.nodeList.map((n) => n.level));
      ctx.textAlign = "left";
      for (const level of [4, 3, 2, 1]) {
        if (!levels.has(level)) continue;
        const y = NetGraph.LEVEL_Y[level] - 130;
        ctx.globalAlpha = 1;
        ctx.fillStyle = level % 2 ? "rgba(112,167,255,.045)" : "rgba(69,214,203,.035)";
        ctx.fillRect(vx0, y, vx1 - vx0, 260);
        ctx.strokeStyle = "rgba(133,154,183,.16)";
        ctx.lineWidth = px;
        ctx.beginPath(); ctx.moveTo(vx0, y); ctx.lineTo(vx1, y); ctx.stroke();
        // Band titles stay readable at any zoom: drawn at a fixed screen size at the left edge.
        ctx.font = `600 ${12 * px}px 'Segoe UI', 'Malgun Gothic', sans-serif`;
        ctx.fillStyle = "#8fb4ff";
        ctx.fillText(NetGraph.LEVEL_LABEL[level], vx0 + 60 + 12 * px, y + 20 * px);
      }
    }
    ctx.globalAlpha = 1;
  }

  static arrow(p, x, y, ux, uy) {
    const s = 7;
    p.moveTo(x, y);
    p.lineTo(x - ux * s - uy * s * 0.5, y - uy * s + ux * s * 0.5);
    p.lineTo(x - ux * s + uy * s * 0.5, y - uy * s - ux * s * 0.5);
    p.closePath();
  }
}

NetGraph.MAX_PARTICLES = 2500;
/** Traffic level of a link from packets per second: 0 idle, 1 low, 2 normal, 3 high, 4 very high. */
NetGraph.tier = (rate) => (rate <= 0 ? 0 : rate < 1 ? 1 : rate < 10 ? 2 : rate < 100 ? 3 : 4);
NetGraph.HEAT = ["#53647b", "#6f8fc0", "#45d6cb", "#f2d06b", "#ff9f5a"];
NetGraph.EXTERNAL = "~internet";
NetGraph.LEVEL_Y = { 4: -420, 3: -140, 2: 140, 1: 420 };
NetGraph.LEVEL_LABEL = {
  4: "Level 4–5 · 외부망 / 인터넷",
  3: "Level 3 · 운영·IT망 (미분류 포함)",
  2: "Level 2 · 감시·제어 (HMI · EWS · SCADA)",
  1: "Level 0–1 · 제어기·현장 장비 (PLC · RTU · I/O)",
};
NetGraph.MIN_ZOOM = 0.08;
NetGraph.MAX_ZOOM = 6;
NetGraph.C = {
  edge: "#53647b", edgeActive: "#6f86a3", edgeLabel: "#8394aa", red: "#ff6b6b", cyan: "#45d6cb",
  req: "#45d6cb", resp: "#70a7ff",
};
NetGraph.STYLES = {
  plc: { fill: "#16363a", stroke: "#45d6cb" },
  power: { fill: "#2e2a16", stroke: "#f2d06b" },
  workstation: { fill: "#1b2a48", stroke: "#70a7ff" },
  building: { fill: "#2a2941", stroke: "#a99cff" },
  industrial: { fill: "#332b20", stroke: "#ffba68" },
  unknown: { fill: "#192a40", stroke: "#6d819b" },
  external: { fill: "#221f3a", stroke: "#a99cff" },
};
