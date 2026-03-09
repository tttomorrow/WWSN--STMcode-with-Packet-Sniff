HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>WWSN Control Console</title>
  <style>
    :root {
      --bg: #eff4fb;
      --ink: #0f172a;
      --muted: #64748b;
      --panel: #ffffff;
      --stroke: #d7e2f1;
      --accent: #2563eb;
      --accent-2: #0ea5e9;
      --ok: #16a34a;
      --bad: #dc2626;
      --warn: #d97706;
      --shadow: 0 14px 30px rgba(15, 23, 42, 0.08);
      --radius: 14px;
      --font-body: "Avenir Next", "SF Pro Text", "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
      --font-display: "Avenir Next", "SF Pro Display", "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
    }

    * { box-sizing: border-box; }
    html, body { height: 100%; }
    body {
      margin: 0;
      color: var(--ink);
      font-family: var(--font-body);
      background:
        radial-gradient(1200px 620px at 110% -10%, rgba(37,99,235,0.18), rgba(37,99,235,0) 60%),
        radial-gradient(900px 520px at -10% 0%, rgba(14,165,233,0.14), rgba(14,165,233,0) 55%),
        linear-gradient(180deg, #f8fbff 0%, var(--bg) 100%);
      overflow: hidden;
    }

    .wrap {
      width: 100%;
      max-width: 2380px;
      margin: 0 auto;
      height: 100vh;
      padding: 10px 12px;
      display: grid;
      grid-template-rows: auto auto 1fr;
      gap: 10px;
    }

    .hero {
      display: block;
      margin-bottom: 0;
      min-height: 0;
    }
    .hero-text { min-height: 0; display: flex; flex-direction: column; }
    .kicker {
      text-transform: uppercase;
      letter-spacing: 0.14em;
      color: #1d4ed8;
      font-size: 11px;
      font-weight: 600;
    }
    h1 {
      font-family: var(--font-display);
      font-size: 34px;
      line-height: 1.08;
      margin: 6px 0 8px;
      letter-spacing: 0.01em;
    }
    .lead {
      color: var(--muted);
      font-size: 13px;
      line-height: 1.45;
      max-width: 720px;
    }
    .status-bar {
      margin-top: 8px;
      display: flex;
      flex-wrap: nowrap;
      gap: 10px;
    }
    .status-block {
      background: rgba(255,255,255,0.78);
      border: 1px solid var(--stroke);
      border-radius: 12px;
      padding: 8px 10px;
      min-width: 0;
      flex: 1;
      backdrop-filter: blur(6px);
    }
    .label {
      display: block;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      font-size: 10px;
      color: var(--muted);
      font-weight: 600;
    }
    .status {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 10px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.12em;
      margin-right: 6px;
    }
    .status--ok { background: rgba(22,163,74,0.12); color: var(--ok); border: 1px solid rgba(22,163,74,0.28); }
    .status--bad { background: rgba(220,38,38,0.1); color: var(--bad); border: 1px solid rgba(220,38,38,0.24); }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; font-weight: 700; }
    .badge--ok { background: rgba(22,163,74,0.12); color: var(--ok); border: 1px solid rgba(22,163,74,0.28); }
    .badge--bad { background: rgba(220,38,38,0.1); color: var(--bad); border: 1px solid rgba(220,38,38,0.24); }
    .badge--warn { background: rgba(217,119,6,0.12); color: var(--warn); border: 1px solid rgba(217,119,6,0.24); }
    .throughput {
      font-weight: 700;
      font-size: 20px;
      color: #0f4fd6;
    }

    .card {
      background: linear-gradient(180deg, rgba(255,255,255,0.96), rgba(255,255,255,0.9));
      border: 1px solid var(--stroke);
      border-radius: var(--radius);
      padding: 12px;
      box-shadow: var(--shadow);
      position: relative;
      overflow: hidden;
    }
    .card::before {
      content: "";
      position: absolute;
      inset: 0;
      background: linear-gradient(120deg, rgba(37,99,235,0.05), rgba(14,165,233,0.02) 40%, rgba(255,255,255,0) 70%);
      pointer-events: none;
    }

    .layout {
      display: grid;
      grid-template-columns: 0.9fr 1.05fr 1.05fr;
      grid-template-rows: repeat(3, minmax(0, 1fr));
      grid-template-areas:
        "topology node last"
        "topology history sniffer"
        "topology ack cmdlog";
      gap: 10px;
      min-height: 0;
    }
    .layout > .stack { display: contents; }
    .layout .card {
      min-height: 0;
      display: flex;
      flex-direction: column;
    }
    .topology-card { grid-area: topology; }
    .node-status-card { grid-area: node; }
    .last-packets-card { grid-area: last; }
    .history-card { grid-area: history; }
    .sniffer-card { grid-area: sniffer; }
    .recent-acks-card { grid-area: ack; }
    .command-log-card { grid-area: cmdlog; }

    h3 { margin: 0 0 8px; font-family: var(--font-display); font-size: 17px; letter-spacing: 0.01em; }
    .muted { color: var(--muted); }
    .note { margin-top: 8px; font-size: 12px; line-height: 1.45; }

    .form-row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 10px; }
    .command-console-card .cmd-inline {
      flex-wrap: nowrap;
      gap: 10px;
      align-items: center;
    }
    .command-console-card .cmd-inline input,
    .command-console-card .cmd-inline select {
      width: 94px;
      min-width: 94px;
    }
    .command-console-card .cmd-inline #dest { width: 86px; min-width: 86px; }
    .command-console-card .cmd-inline #cmdResult {
      margin-left: 6px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.09em; color: var(--muted); font-weight: 700; }
    input, select {
      border: 1px solid var(--stroke);
      border-radius: 9px;
      padding: 8px 10px;
      background: #fff;
      color: var(--ink);
      font-family: var(--font-body);
      min-width: 86px;
      outline: none;
    }
    input:focus, select:focus {
      border-color: #78a8ff;
      box-shadow: 0 0 0 2px rgba(37,99,235,0.12);
    }
    button {
      border: none;
      background: linear-gradient(135deg, var(--accent), #1d4ed8);
      color: #fff;
      padding: 9px 14px;
      border-radius: 10px;
      font-weight: 700;
      letter-spacing: 0.02em;
      cursor: pointer;
    }
    button:hover { background: linear-gradient(135deg, #1d4ed8, #1e40af); }
    .cmd-result { margin-left: 8px; font-size: 12px; }

    table { width: 100%; border-collapse: collapse; table-layout: auto; }
    th {
      text-align: left;
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
      border-bottom: 1px solid var(--stroke);
      padding: 7px 8px;
      white-space: normal;
      overflow-wrap: anywhere;
    }
    td {
      padding: 7px 8px;
      border-bottom: 1px dashed #e6edf8;
      font-size: 13px;
      white-space: normal;
      overflow-wrap: anywhere;
      word-break: break-word;
      line-height: 1.32;
      vertical-align: top;
    }
    tbody tr:nth-child(odd) { background: rgba(148,163,184,0.08); }

    .topo-canvas {
      width: 100%;
      height: auto;
      flex: 1;
      min-height: 0;
      background: #fbfdff;
      border: 1px solid var(--stroke);
      border-radius: 12px;
    }
    .history-scroll {
      height: auto;
      min-height: 0;
      flex: 1;
      overflow-y: auto;
      overflow-x: hidden;
      border: 1px solid var(--stroke);
      border-radius: 10px;
      background: #fff;
    }
    .history-scroll--compact { height: auto; }
    .command-console-card .history-scroll--compact {
      max-height: clamp(130px, 15vh, 180px);
      min-height: clamp(130px, 15vh, 180px);
      flex: 0 0 clamp(130px, 15vh, 180px);
    }
    .cmd-ref-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 8px;
      padding: 8px;
    }
    .cmd-ref-item {
      border: 1px solid var(--stroke);
      border-radius: 8px;
      background: #f8fbff;
      padding: 7px 8px;
      min-width: 0;
    }
    .cmd-ref-name {
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.03em;
      color: #0f2a56;
      margin-bottom: 2px;
    }
    .cmd-ref-args {
      font-size: 10px;
      color: #64748b;
      margin-bottom: 3px;
      line-height: 1.3;
    }
    .cmd-ref-desc {
      font-size: 11px;
      color: #334155;
      line-height: 1.35;
      overflow-wrap: anywhere;
    }
    .history-scroll table { margin: 0; }
    .history-scroll thead th {
      position: sticky;
      top: 0;
      background: #f5f9ff;
      z-index: 1;
    }
    .history-scroll::-webkit-scrollbar { width: 10px; }
    .history-scroll::-webkit-scrollbar-thumb { background: #c7d6ee; border-radius: 999px; }
    .history-scroll::-webkit-scrollbar-track { background: #eef3fb; }

    @media (max-width: 1280px) {
      .wrap { height: auto; min-height: 100vh; }
      body { overflow: auto; }
      .status-bar { flex-wrap: wrap; }
      .layout {
        grid-template-columns: 1fr;
        grid-template-rows: auto;
        grid-template-areas:
          "topology"
          "node"
          "last"
          "history"
          "sniffer"
          "ack"
          "cmdlog";
      }
      h1 { font-size: 34px; }
      .topo-canvas { min-height: 360px; }
      .command-console-card .history-scroll--compact { min-height: 140px; max-height: 180px; }
      .command-console-card .cmd-inline { flex-wrap: wrap; }
      .command-console-card .cmd-inline input,
      .command-console-card .cmd-inline select { width: auto; min-width: 90px; }
      .cmd-ref-grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <header class="hero">
      <div class="hero-text">
        <div class="kicker">WWSN Control Console</div>
        <h1>Wireless Weak-link Network</h1>
        <div class="lead">Real-time monitoring for sensor traffic, route quality, and command effectiveness across your WWSN deployment.</div>
        <div class="status-bar">
          <div class="status-block">
            <span class="label">TCP</span>
            <span id="connStatus" class="status status--bad">disconnected</span>
            <span id="connAddr" class="muted"></span>
          </div>
          <div class="status-block">
            <span class="label">Link</span>
            <span id="linkMode" class="status status--bad">none</span>
            <span id="serialStatus" class="muted"></span>
          </div>
          <div class="status-block">
            <span class="label">Throughput</span>
            <span class="throughput"><span id="throughput">0</span> MB/s</span>
          </div>
        </div>
      </div>
    </header>

    <div class="card command-console-card">
      <h3>Command Console</h3>
      <div class="form-row cmd-inline">
        <label>Dest ID</label>
        <input id="dest" type="number" value="255" min="0" max="255" />
        <label>Command</label>
        <select id="cmd">
          <option value="MODE">MODE</option>
          <option value="ROUND">ROUND</option>
          <option value="ONOFF">ONOFF</option>
          <option value="ROUTE">ROUTE</option>
          <option value="DROP">DROP</option>
        </select>
        <label>P1</label>
        <input id="p1" type="number" value="0" />
        <label>P2</label>
        <input id="p2" type="number" value="0" />
        <button onclick="sendCmd()">Send</button>
        <span id="cmdResult" class="muted cmd-result"></span>
      </div>
      <div class="note muted" style="margin-top: 2px;">
        Dest ID `255` = broadcast; unicast first tries routing, and falls back to broadcast when route is missing.<br/>
        ACK timeout: <span id="ackTimeout">-</span>s, auto-retry up to <span id="ackRetry">-</span> times.
      </div>
      <div class="history-scroll history-scroll--compact">
        <div class="cmd-ref-grid">
          <div class="cmd-ref-item">
            <div class="cmd-ref-name">MODE</div>
            <div class="cmd-ref-args">P1: 0/1, P2: 1/2/3</div>
            <div class="cmd-ref-desc">P1=0 normal, P1=1 malicious. P2 selects malicious type.</div>
          </div>
          <div class="cmd-ref-item">
            <div class="cmd-ref-name">ROUND</div>
            <div class="cmd-ref-args">P1: ms, P2: -</div>
            <div class="cmd-ref-desc">Sampling and uplink period in ms, range 1000-600000.</div>
          </div>
          <div class="cmd-ref-item">
            <div class="cmd-ref-name">ONOFF</div>
            <div class="cmd-ref-args">P1: 0/1, P2: 0/1</div>
            <div class="cmd-ref-desc">P1 enables on-off policy. P2 forces current state (0 off, 1 on).</div>
          </div>
          <div class="cmd-ref-item">
            <div class="cmd-ref-name">ROUTE</div>
            <div class="cmd-ref-args">P1: -, P2: -</div>
            <div class="cmd-ref-desc">Clear route cache and rebuild paths.</div>
          </div>
          <div class="cmd-ref-item">
            <div class="cmd-ref-name">DROP</div>
            <div class="cmd-ref-args">P1: 0/1/2, P2: 0-100</div>
            <div class="cmd-ref-desc">P1: 0 normal, 1 drop-all, 2 random-drop. P2 is drop rate.</div>
          </div>
        </div>
      </div>
      <div class="note muted">ACK: ACK,A,seq,cmd,status,nodeID | STATUS: STAT,S,nodeID,roundTime,onoffEnabled,onoffOn,isMalicious,maliciousType,dropPolicy,dropRate.</div>
    </div>

    <section class="layout">
      <div class="stack">
        <div class="card topology-card">
          <h3>Network Topology</h3>
          <canvas id="topo" class="topo-canvas"></canvas>
          <div class="note muted">Topology is generated from recent path traces; nodes not refreshed for 30s are dimmed. Use mouse wheel to zoom, double-click to reset.</div>
        </div>
      </div>

      <div class="stack">
        <div class="card node-status-card">
          <h3>Node Status</h3>
          <div class="history-scroll">
            <table>
              <thead><tr><th>ID</th><th>Online</th><th>Round</th><th>OnOff</th><th>Mode</th><th>Drop</th></tr></thead>
              <tbody id="nodeStatus"></tbody>
            </table>
          </div>
        </div>
        <div class="card last-packets-card">
          <h3>Last Packets</h3>
          <div class="history-scroll">
            <table>
              <thead><tr><th>ID</th><th>Temp</th><th>Hum</th><th>Time</th></tr></thead>
              <tbody id="packetTable"></tbody>
            </table>
          </div>
        </div>
        <div class="card history-card">
          <h3>History Packets</h3>
          <div class="form-row">
            <label>Node ID</label>
            <input id="histNode" type="number" min="1" max="255" placeholder="all" />
            <label>Limit</label>
            <input id="histLimit" type="number" min="1" max="500" value="50" />
            <button onclick="queryHistory()">Query</button>
          </div>
          <div class="history-scroll">
            <table>
              <thead><tr><th>DBID</th><th>Node</th><th>Proto</th><th>Pkt</th><th>Temp</th><th>Hum</th><th>Mal</th><th>MType</th><th>Time</th></tr></thead>
              <tbody id="historyTable"></tbody>
            </table>
          </div>
        </div>
        <div class="card sniffer-card">
          <h3>Sniffer Packets</h3>
          <div class="form-row">
            <label>Sniffer ID</label>
            <input id="snfSniffer" type="number" min="1" max="255" placeholder="all" />
            <label>Source ID</label>
            <input id="snfSource" type="number" min="1" max="255" placeholder="all" />
            <label>Limit</label>
            <input id="snfLimit" type="number" min="1" max="500" value="100" />
            <button onclick="querySniffer()">Query</button>
          </div>
          <div class="history-scroll">
            <table>
              <thead><tr><th>ID</th><th>Sniffer</th><th>Source</th><th>Last RSSI</th><th>Summary</th><th>Time</th></tr></thead>
              <tbody id="snifferTable"></tbody>
            </table>
          </div>
        </div>
        <div class="card recent-acks-card">
          <h3>Recent ACKs</h3>
          <div class="history-scroll history-scroll--compact">
            <table>
              <thead><tr><th>Node</th><th>Cmd</th><th>Seq</th><th>Status</th><th>Time</th></tr></thead>
              <tbody id="ackTable"></tbody>
            </table>
          </div>
        </div>
        <div class="card command-log-card">
          <h3>Command Log</h3>
          <div class="history-scroll history-scroll--compact">
            <table>
              <thead><tr><th>Dest</th><th>Cmd</th><th>P1</th><th>P2</th><th>Seq</th><th>Status</th><th>Retry</th><th>Time</th></tr></thead>
              <tbody id="cmdLog"></tbody>
            </table>
          </div>
        </div>
      </div>
    </section>
  </div>

  <script>
    const topoRenderState = {
      topology: {nodes: [], edges: []},
      statusList: [],
      lastPackets: []
    };
    const topoView = {
      scale: 1.0,
      minScale: 0.6,
      maxScale: 3.5,
      offsetX: 0,
      offsetY: 0,
      bound: false
    };

    function clampValue(v, minV, maxV) {
      return Math.max(minV, Math.min(maxV, v));
    }

    function installTopoInteractions() {
      if (topoView.bound) return;
      const canvas = document.getElementById('topo');
      if (!canvas) return;
      topoView.bound = true;

      canvas.addEventListener('wheel', (ev) => {
        ev.preventDefault();
        const w = Math.max(320, Math.floor(canvas.clientWidth || 800));
        const h = Math.max(240, Math.floor(canvas.clientHeight || 360));
        const rect = canvas.getBoundingClientRect();
        const mx = ev.clientX - rect.left;
        const my = ev.clientY - rect.top;
        const cx = w / 2;
        const cy = h / 2;
        const factor = ev.deltaY < 0 ? 1.12 : 0.89;
        const prev = topoView.scale;
        const next = clampValue(prev * factor, topoView.minScale, topoView.maxScale);
        if (next === prev) return;

        const worldX = (mx - cx - topoView.offsetX) / prev;
        const worldY = (my - cy - topoView.offsetY) / prev;
        topoView.scale = next;
        topoView.offsetX = mx - cx - worldX * next;
        topoView.offsetY = my - cy - worldY * next;
        drawTopology(topoRenderState.topology, topoRenderState.statusList, topoRenderState.lastPackets);
      }, { passive: false });

      canvas.addEventListener('dblclick', () => {
        topoView.scale = 1.0;
        topoView.offsetX = 0;
        topoView.offsetY = 0;
        drawTopology(topoRenderState.topology, topoRenderState.statusList, topoRenderState.lastPackets);
      });
    }

    async function refresh() {
      const res = await fetch('/status');
      const data = await res.json();
      const statusEl = document.getElementById('connStatus');
      statusEl.textContent = data.connected ? 'connected' : 'disconnected';
      statusEl.className = data.connected ? 'status status--ok' : 'status status--bad';
      document.getElementById('connAddr').textContent = data.addr || '';
      document.getElementById('throughput').textContent = (data.last_throughput || 0).toFixed(4);
      const link = data.link || 'none';
      const linkEl = document.getElementById('linkMode');
      if (linkEl) {
        linkEl.textContent = link;
        linkEl.className = link === 'none' ? 'status status--bad' : 'status status--ok';
      }
      const serialEl = document.getElementById('serialStatus');
      if (serialEl) {
        const serialOpen = !!(data.serial && data.serial.open);
        if (link === 'tcp') {
          serialEl.textContent = 'tcp socket active';
        } else if (link === 'serial') {
          serialEl.textContent = serialOpen ? `serial open ${data.serial.port}` : 'serial closed';
        } else {
          serialEl.textContent = serialOpen ? `serial standby ${data.serial.port}` : 'idle';
        }
      }
      const ackTimeout = document.getElementById('ackTimeout');
      const ackRetry = document.getElementById('ackRetry');
      if (ackTimeout && data.cmd_retry) {
        ackTimeout.textContent = data.cmd_retry.timeout;
      }
      if (ackRetry && data.cmd_retry) {
        ackRetry.textContent = data.cmd_retry.max;
      }

      const pktBody = document.getElementById('packetTable');
      pktBody.innerHTML = '';
      data.last_packets.forEach(p => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${p.sourceID}</td><td>${p.temperature}</td><td>${p.humidity}</td><td>${p.timestamp}</td>`;
        pktBody.appendChild(tr);
      });

      const ackBody = document.getElementById('ackTable');
      ackBody.innerHTML = '';
      data.recent_acks.forEach(a => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${a.node}</td><td>${a.cmd}</td><td>${a.seq}</td><td>${a.status}</td><td>${a.time}</td>`;
        ackBody.appendChild(tr);
      });

      const logBody = document.getElementById('cmdLog');
      logBody.innerHTML = '';
      data.cmd_log.forEach(c => {
        const tr = document.createElement('tr');
        const statusText = c.status || 'pending';
        const statusBadge = statusText === 'acked'
          ? '<span class="badge badge--ok">acked</span>'
          : (statusText === 'failed'
            ? '<span class="badge badge--bad">failed</span>'
            : `<span class="badge badge--warn">${statusText}</span>`);
        tr.innerHTML = `<td>${c.dest}</td><td>${c.cmd}</td><td>${c.p1}</td><td>${c.p2}</td><td>${c.seq}</td><td>${statusBadge}</td><td>${c.retries || 0}</td><td>${c.time}</td>`;
        logBody.appendChild(tr);
      });

      const nodeBody = document.getElementById('nodeStatus');
      if (nodeBody) {
        nodeBody.innerHTML = '';
        data.node_status.forEach(n => {
          const tr = document.createElement('tr');
          const onlineBadge = n.online ? '<span class="badge badge--ok">online</span>' : '<span class="badge badge--bad">offline</span>';
          const modeText = n.isMalicious ? `malicious-${n.maliciousType || 1}` : 'normal';
          const onoffText = n.onoffEnabled
            ? (n.onoffOn ? 'on' : 'off')
            : 'disabled';
          const dropText = n.dropPolicy
            ? (n.dropPolicy === 1 ? 'drop-all' : `drop-${n.dropRate || 0}%`)
            : 'normal';
          tr.innerHTML = `<td>${n.id}</td><td>${onlineBadge}</td><td>${n.roundTime || '-'}</td><td>${onoffText}</td><td>${modeText}</td><td>${dropText}</td>`;
          nodeBody.appendChild(tr);
        });
      }

      topoRenderState.topology = data.topology || {nodes: [], edges: []};
      topoRenderState.statusList = data.node_status || [];
      topoRenderState.lastPackets = data.last_packets || [];
      drawTopology(topoRenderState.topology, topoRenderState.statusList, topoRenderState.lastPackets);
    }

    function drawTopology(topology, statusList, lastPackets) {
      const canvas = document.getElementById('topo');
      if (!canvas) return;
      installTopoInteractions();
      const ctx = canvas.getContext('2d');
      const w = Math.max(320, Math.floor(canvas.clientWidth || 800));
      const h = Math.max(240, Math.floor(canvas.clientHeight || 360));
      const dpr = Math.max(1, window.devicePixelRatio || 1);
      const rw = Math.floor(w * dpr);
      const rh = Math.floor(h * dpr);
      if (canvas.width !== rw) canvas.width = rw;
      if (canvas.height !== rh) canvas.height = rh;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);

      const nodes = (topology && topology.nodes) ? topology.nodes : [];
      const edges = (topology && topology.edges) ? topology.edges : [];
      if (nodes.length === 0) {
        ctx.fillStyle = '#64748b';
        ctx.font = '600 14px "Avenir Next", "Segoe UI", "PingFang SC", sans-serif';
        ctx.fillText('no topology data yet', 10, 20);
        return;
      }

      const now = Date.now() / 1000;
      const center = {x: w / 2, y: h / 2};
      const radius = Math.min(w, h) / 2 - 40;
      const pos = {};

      const sink = nodes.find(n => n.id === 1);
      if (sink) {
        pos[1] = center;
      }
      const others = nodes.filter(n => n.id !== 1);
      const count = others.length;
      others.forEach((n, i) => {
        const ang = (2 * Math.PI * i) / Math.max(count, 1);
        pos[n.id] = {
          x: center.x + radius * Math.cos(ang),
          y: center.y + radius * Math.sin(ang)
        };
      });

      ctx.save();
      ctx.translate(center.x + topoView.offsetX, center.y + topoView.offsetY);
      ctx.scale(topoView.scale, topoView.scale);
      ctx.translate(-center.x, -center.y);

      ctx.strokeStyle = '#c8d8ef';
      ctx.lineWidth = 1.2;
      edges.forEach(e => {
        const a = pos[e.a];
        const b = pos[e.b];
        if (!a || !b) return;
        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(b.x, b.y);
        ctx.stroke();
      });

      const statusMap = {};
      (statusList || []).forEach(n => { statusMap[n.id] = n; });
      const packetMap = {};
      (lastPackets || []).forEach(p => { packetMap[p.sourceID] = p; });

      nodes.forEach(n => {
        const p = pos[n.id];
        if (!p) return;
        const age = now - n.last_seen;
        const isSink = n.id === 1;
        const stat = statusMap[n.id] || {};
        const online = Object.prototype.hasOwnProperty.call(statusMap, n.id) ? !!stat.online : (age <= 30);
        const isMalicious = !!stat.isMalicious;
        const baseColor = isSink ? '#2b6cff' : (isMalicious ? '#d93025' : '#1b9e3f');
        ctx.globalAlpha = online ? 1.0 : 0.45;
        ctx.fillStyle = baseColor;
        ctx.beginPath();
        ctx.arc(p.x, p.y, isSink ? 10 : 8, 0, Math.PI * 2);
        ctx.fill();
        ctx.globalAlpha = 1.0;
        ctx.fillStyle = '#1f1f1f';
        ctx.font = '600 13px "Avenir Next", "Segoe UI", "PingFang SC", sans-serif';
        ctx.fillText(String(n.id), p.x + 10, p.y - 10);
        const latest = packetMap[n.id];
        if (latest) {
          const t = Number(latest.temperature);
          const h = Number(latest.humidity);
          const tempText = Number.isFinite(t) ? t.toFixed(1) : '-';
          const humText = Number.isFinite(h) ? h.toFixed(1) : '-';
          ctx.fillStyle = '#475569';
          ctx.font = '500 11px "Avenir Next", "Segoe UI", "PingFang SC", sans-serif';
          ctx.fillText(`T:${tempText} H:${humText}`, p.x + 10, p.y + 4);
        }
        if (isSink) {
          ctx.fillStyle = '#2b6cff';
          ctx.font = '700 12px "Avenir Next", "Segoe UI", "PingFang SC", sans-serif';
          ctx.fillText('SINK', p.x + 12, p.y + 14);
        }
      });
      ctx.restore();
    }

    async function queryHistory() {
      const nodeRaw = (document.getElementById('histNode').value || '').trim();
      const limitRaw = parseInt(document.getElementById('histLimit').value || '50', 10);
      const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(500, limitRaw)) : 50;
      const q = new URLSearchParams();
      q.set('limit', String(limit));
      if (nodeRaw !== '') q.set('node', nodeRaw);
      const res = await fetch('/history?' + q.toString());
      const data = await res.json();
      const body = document.getElementById('historyTable');
      body.innerHTML = '';
      (data.rows || []).forEach(r => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${r.id}</td><td>${r.sourceID}</td><td>${r.protocolName}</td><td>${r.packetID}</td><td>${r.temperature}</td><td>${r.humidity}</td><td>${r.isMalicious}</td><td>${r.maliciousType}</td><td>${r.timestamp}</td>`;
        body.appendChild(tr);
      });
    }

    async function querySniffer() {
      const snifferRaw = (document.getElementById('snfSniffer').value || '').trim();
      const sourceRaw = (document.getElementById('snfSource').value || '').trim();
      const limitRaw = parseInt(document.getElementById('snfLimit').value || '100', 10);
      const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(500, limitRaw)) : 100;
      const q = new URLSearchParams();
      q.set('limit', String(limit));
      if (snifferRaw !== '') q.set('sniffer', snifferRaw);
      if (sourceRaw !== '') q.set('source', sourceRaw);
      const res = await fetch('/sniffer_history?' + q.toString());
      const data = await res.json();
      const body = document.getElementById('snifferTable');
      body.innerHTML = '';
      (data.rows || []).forEach(r => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${r.id}</td><td>${r.snifferID}</td><td>${r.sourceID}</td><td>${r.lastRSSI}</td><td>${r.summary}</td><td>${r.timestamp}</td>`;
        body.appendChild(tr);
      });
    }

    async function sendCmd() {
      const dest = parseInt(document.getElementById('dest').value, 10);
      const cmd = document.getElementById('cmd').value;
      const p1 = parseInt(document.getElementById('p1').value, 10);
      const p2 = parseInt(document.getElementById('p2').value, 10);
      const res = await fetch('/command', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({dest, cmd, p1, p2})
      });
      const data = await res.json();
      document.getElementById('cmdResult').textContent = data.ok ? `sent (seq ${data.seq})` : `error: ${data.error}`;
    }

    setInterval(refresh, 1000);
    refresh();
    queryHistory();
    querySniffer();
  </script>
</body>
</html>
"""
