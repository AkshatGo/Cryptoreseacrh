'use strict';

/* ==========================================================================
   pqbench lab — simulation engine
   The numbers are a cost model over the pqbench harness:
   tx = 100 B payload + length + signature; block = header + seal + N tx.
   ========================================================================== */

const TX = {
  payloadB: 100,
  headerB: 84,
  gcmB: 28,          // 12-byte nonce + 16-byte tag
  overheadMs: 0.27,  // AES-GCM work + loopback ack, held constant
};

const SIGS = [
  {
    id: 'ECDSA-P256', family: 'classical', measured: true,
    blurb: 'NIST P-256 · ECDSA/SHA-256',
    pk: 65, sk: 32, sig: 70.9,
    keygen: 0.0220, sign: 0.0271, verify: 0.0959,
  },
  {
    id: 'ML-DSA-44', family: 'pq',
    blurb: 'FIPS 204 · lattice',
    pk: 1312, sk: 2560, sig: 2420,
    keygen: 0.09, sign: 0.18, verify: 0.07,
  },
  {
    id: 'ML-DSA-65', family: 'pq',
    blurb: 'FIPS 204 · lattice',
    pk: 1952, sk: 4032, sig: 3309,
    keygen: 0.13, sign: 0.29, verify: 0.10,
  },
  {
    id: 'ML-DSA-87', family: 'pq',
    blurb: 'FIPS 204 · lattice',
    pk: 2592, sk: 4896, sig: 4627,
    keygen: 0.20, sign: 0.44, verify: 0.15,
  },
  {
    id: 'Falcon-512', family: 'pq',
    blurb: 'NIST PQC · NTRU lattice',
    pk: 897, sk: 1281, sig: 666,
    keygen: 8.5, sign: 0.42, verify: 0.035,
  },
  {
    id: 'Falcon-1024', family: 'pq',
    blurb: 'NIST PQC · NTRU lattice',
    pk: 1793, sk: 2305, sig: 1280,
    keygen: 18.0, sign: 0.85, verify: 0.055,
  },
  {
    id: 'SLH-DSA-SHAKE-128f', family: 'pq',
    blurb: 'FIPS 205 · hash-based · fast',
    pk: 32, sk: 64, sig: 17088,
    keygen: 1.4, sign: 19.5, verify: 1.1,
  },
  {
    id: 'SLH-DSA-SHAKE-128s', family: 'pq',
    blurb: 'FIPS 205 · hash-based · small',
    pk: 32, sk: 64, sig: 29792,
    keygen: 9.0, sign: 290, verify: 2.4,
  },
];

const KEMS = [
  {
    id: 'ECDH-P256', family: 'classical', measured: true,
    blurb: 'NIST P-256 · ECDH',
    pk: 65, sk: 32, ct: 65, ss: 32,
    keygen: 0.0219, encaps: 0.1113, decaps: 0.0727,
  },
  {
    id: 'ML-KEM-512', family: 'pq',
    blurb: 'FIPS 203 · lattice',
    pk: 800, sk: 1632, ct: 768, ss: 32,
    keygen: 0.012, encaps: 0.016, decaps: 0.018,
  },
  {
    id: 'ML-KEM-768', family: 'pq',
    blurb: 'FIPS 203 · lattice',
    pk: 1184, sk: 2400, ct: 1088, ss: 32,
    keygen: 0.018, encaps: 0.023, decaps: 0.025,
  },
  {
    id: 'ML-KEM-1024', family: 'pq',
    blurb: 'FIPS 203 · lattice',
    pk: 1568, sk: 3168, ct: 1568, ss: 32,
    keygen: 0.027, encaps: 0.032, decaps: 0.035,
  },
];

/* ------------------------------------------------------------------ helpers */
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const MONO = 'ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace';

function clamp(n, lo, hi) { return Math.max(lo, Math.min(hi, n)); }

function mulberry32(seed) {
  let a = seed >>> 0;
  return function () {
    a = (a + 0x6D2B79F5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), 1 | t);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function hashStr(str) {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

function hashHex(seed, bytes = 8) {
  const rng = mulberry32(hashStr(String(seed)));
  let out = '';
  for (let i = 0; i < bytes; i++) out += Math.floor(rng() * 256).toString(16).padStart(2, '0');
  return out;
}

function jitter(base, rng, spread = 0.2) {
  return base * Math.max(0.35, 1 + (rng() * 2 - 1) * spread);
}

function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, ch => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[ch]));
}

function fmtMs(ms) {
  if (!isFinite(ms)) return '—';
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)} s`;
  if (ms >= 100) return `${ms.toFixed(0)} ms`;
  if (ms >= 10) return `${ms.toFixed(1)} ms`;
  if (ms >= 1) return `${ms.toFixed(2)} ms`;
  if (ms >= 0.01) return `${ms.toFixed(3)} ms`;
  return `${(ms * 1000).toFixed(1)} µs`;
}

function fmtMsShort(ms) {
  if (!isFinite(ms)) return '—';
  if (ms >= 1000) return `${(ms / 1000).toFixed(1)}s`;
  if (ms >= 100) return `${Math.round(ms)}ms`;
  if (ms >= 10) return `${ms.toFixed(0)}ms`;
  if (ms >= 1) return `${ms.toFixed(1)}ms`;
  if (ms >= 0.01) return `${(ms * 1000).toFixed(0)}µs`;
  return `${(ms * 1000).toFixed(1)}µs`;
}

function fmtBytes(bytes) {
  if (!isFinite(bytes)) return '—';
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(1)} MB`;
  if (bytes >= 10000) return `${Math.round(bytes / 1000)} KB`;
  if (bytes >= 1000) return `${(bytes / 1000).toFixed(1)} KB`;
  return `${Math.round(bytes)} B`;
}

function fmtInt(n) {
  return Math.round(n).toLocaleString('en-US');
}

function fmtClock(ms) {
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)} s`;
  if (ms >= 10) return `${ms.toFixed(1)} ms`;
  if (ms >= 1) return `${ms.toFixed(2)} ms`;
  return `${(ms * 1000).toFixed(0)} µs`;
}

function fmtLogTime(ms) {
  return `t+${(ms / 1000).toFixed(3)}s`;
}

/* -------------------------------------------------------------------- model */
function algById(list, id) { return list.find(a => a.id === id); }

function readConfig() {
  return {
    kem: algById(KEMS, $('#kem-select').value) || KEMS[0],
    sig: algById(SIGS, $('#sig-select').value) || SIGS[0],
    txCount: parseInt($('#tx-select').value, 10) || 120,
    blockSize: parseInt($('#block-select').value, 10) || 20,
    speed: state.speed,
  };
}

function projection(cfg) {
  const { sig, kem, txCount, blockSize } = cfg;
  const txBytes = TX.payloadB + 2 + sig.sig;
  const wireBytes = txBytes + TX.gcmB;
  const blockBytes = TX.headerB + 2 + sig.sig + blockSize * txBytes;
  const share = ((blockSize + 1) * sig.sig / blockBytes) * 100;
  const perTxMs = sig.sign + sig.verify + TX.overheadMs;
  const throughput = 1000 / perTxMs;
  const sessionBytes = kem.pk + kem.ct + sig.pk;
  const handshakeMs = kem.keygen + kem.encaps + kem.decaps + 2 * sig.keygen + 0.22;
  const blocks = Math.max(1, Math.round(txCount / blockSize));
  const chainVerifyMs = (txCount + blocks) * sig.verify + blocks * 0.03;
  return {
    txBytes, wireBytes, blockBytes, share, perTxMs, throughput,
    sessionBytes, handshakeMs, blocks, chainVerifyMs,
  };
}

/* --------------------------------------------------------------------- state */
const state = {
  view: 'sim',
  speed: 2,
  running: false,
  run: null,
  raf: 0,
  tampered: false,
  selectedBlock: null,
  packets: new Set(),
  bench: {
    done: false,
    running: false,
    sigs: null,
    kems: null,
    n: 0,
    started: false,
  },
};

/* ------------------------------------------------------------------ init DOM */
const els = {};

function cacheEls() {
  const ids = [
    'kem-select', 'sig-select', 'tx-select', 'block-select', 'speed-group',
    'run-btn', 'run-icon', 'run-label', 'config-note', 'profile-badge',
    'stat-throughput', 'stat-txsize', 'stat-txsize-sub', 'stat-blocksize',
    'stat-blocksize-sub', 'stat-share', 'stat-sign', 'stat-verify',
    'stage', 'stage-sub', 'chain-pill', 'session-pill', 'top-dot', 'top-status-text',
    'dev-sign', 'dev-size', 'gw-verify', 'gw-seal', 'chain-sub', 'chain-size', 'chain-share',
    'progress-fill', 'progress-label', 'sim-clock',
    'chain-view', 'inspector', 'chain-alert', 'tamper-btn', 'export-btn',
    'log', 'log-count', 'node-device', 'node-gateway', 'node-chain',
    'bench-btn', 'bench-btn-label', 'bench-status', 'bench-progress', 'bench-badge',
    'samples-select', 'sig-table-body', 'kem-table-body', 'sig-table-badge', 'kem-table-badge',
    'bench-fastest-sign', 'bench-fastest-sign-sub', 'bench-fastest-verify',
    'bench-fastest-verify-sub', 'bench-smallest-sig', 'bench-smallest-sig-sub',
    'bench-largest-sig', 'bench-largest-sig-sub',
    'chart-latency', 'chart-size',
  ];
  ids.forEach(id => { els[id] = document.getElementById(id); });
  els.topStatus = $('.top-status');
  els.runBtn = els['run-btn'];
  els.stage = els['stage'];
  els.runBtn.classList.remove('is-running');
  els.stage.classList.remove('is-running', 'is-done');
}

function fillSelect(select, items, selected) {
  const groups = {
    classical: document.createElement('optgroup'),
    pq: document.createElement('optgroup'),
  };
  groups.classical.label = 'Classical';
  groups.pq.label = 'Post-quantum';
  items.forEach(item => {
    const option = document.createElement('option');
    option.value = item.id;
    option.textContent = item.id;
    if (item.measured) option.textContent += '  ·  measured';
    groups[item.family].append(option);
  });
  select.append(groups.classical, groups.pq);
  select.value = selected;
}

function initSelects() {
  fillSelect(els['kem-select'], KEMS, 'ECDH-P256');
  fillSelect(els['sig-select'], SIGS, 'ECDSA-P256');
}

/* --------------------------------------------------------------- pills, status */
function setPill(el, kind, text) {
  if (!el) return;
  el.className = `pill${kind ? ` ${kind}` : ''}`;
  el.replaceChildren();
  const dot = document.createElement('i');
  el.append(dot, document.createTextNode(text));
}

function setTopStatus(text, mode) {
  if (!els['top-status-text']) return;
  els['top-status-text'].textContent = text;
  els.topStatus.classList.toggle('is-busy', mode === 'busy');
  els.topStatus.classList.toggle('is-error', mode === 'error');
}

/* ------------------------------------------------------------------ projection */
function updateProjection() {
  const cfg = readConfig();
  const p = projection(cfg);

  els['stat-throughput'].textContent = fmtInt(p.throughput);
  els['stat-txsize'].textContent = `${Math.round(p.txBytes)} B`;
  els['stat-txsize-sub'].textContent = `${Math.round(p.wireBytes)} B on the wire`;
  els['stat-blocksize'].textContent = fmtBytes(p.blockBytes);
  els['stat-blocksize-sub'].textContent = `${cfg.blockSize} tx · ${p.blocks} block${p.blocks === 1 ? '' : 's'}`;
  els['stat-share'].textContent = `${p.share.toFixed(1)}%`;
  els['stat-sign'].textContent = fmtMs(cfg.sig.sign);
  els['stat-verify'].textContent = fmtMs(cfg.sig.verify);

  els['dev-sign'].textContent = `${fmtMs(cfg.sig.sign)} sign`;
  els['dev-size'].textContent = `${Math.round(p.txBytes)} B tx`;
  els['gw-verify'].textContent = `${fmtMs(cfg.sig.verify)} verify`;
  els['gw-seal'].textContent = `${fmtMs(cfg.sig.sign)} seal`;
  els['chain-sub'].textContent = `${p.blocks} block${p.blocks === 1 ? '' : 's'} expected`;
  els['chain-size'].textContent = `${fmtBytes(p.blockBytes)} / block`;
  els['chain-share'].textContent = `${p.share.toFixed(1)}% sig`;

  const measured = cfg.kem.measured && cfg.sig.measured;
  els['profile-badge'].textContent = measured ? 'measured' : 'reference profile';
  els['profile-badge'].className = `badge ${measured ? 'ok' : 'warn'}`;

  const slow = cfg.sig.id.endsWith('128s') ? ' · slow scheme' : '';
  els['config-note'].textContent =
    `${p.blocks} blocks · session ${fmtBytes(p.sessionBytes)} · handshake ≈ ${fmtMs(p.handshakeMs)}${slow}`;

  if (!state.running) {
    setPill(els['chain-pill'], '', 'chain · idle');
    setPill(els['session-pill'], '', `session · ${fmtBytes(p.sessionBytes)}`);
    if (!state.run) {
      els['stage-sub'].textContent = `Ready — ${cfg.sig.id} over ${cfg.kem.id}. ${cfg.txCount} tx, ${cfg.blockSize} per block.`;
    }
  }
}

/* ------------------------------------------------------------------ log */
function log(message, kind = '', at = null) {
  const el = document.createElement('div');
  el.className = `log-line${kind ? ` ${kind}` : ''}`;
  const time = document.createElement('span');
  time.className = 'log-time';
  time.textContent = at == null ? 'sys' : fmtLogTime(at);
  const msg = document.createElement('span');
  msg.className = 'log-msg';
  msg.textContent = message;
  el.append(time, msg);
  els.log.append(el);
  while (els.log.children.length > 150) els.log.firstElementChild.remove();
  els['log-count'].textContent = `${els.log.children.length} events`;
  els.log.scrollTop = els.log.scrollHeight;
}

function clearLog(message = 'Simulator ready. Select a profile and run.') {
  els.log.replaceChildren();
  log(message, 'muted');
}

/* ---------------------------------------------------------------- packets */
function spawnPacket(wireId, color = '') {
  const wire = document.getElementById(wireId);
  if (!wire) return;
  const packet = document.createElement('span');
  packet.className = `packet${color ? ` ${color}` : ''}`;
  wire.append(packet);
  state.packets.add(packet);
  setTimeout(() => {
    packet.remove();
    state.packets.delete(packet);
  }, 1000);
}

function pulseNode(id, done = false) {
  const node = document.getElementById(id);
  if (!node) return;
  node.classList.add('is-active');
  clearTimeout(node._pulse);
  node._pulse = setTimeout(() => {
    node.classList.remove('is-active');
    if (done || state.running) node.classList.add('is-done');
  }, 160);
}

/* --------------------------------------------------------------- run plan */
function buildPlan(cfg) {
  const p = projection(cfg);
  const rng = mulberry32(hashStr(`${cfg.sig.id}|${cfg.kem.id}|${cfg.txCount}|${cfg.blockSize}|v1`));
  const txs = [];
  const blocks = [];
  let cursor = 0;
  const n = cfg.txCount;
  const bs = cfg.blockSize;

  for (let i = 0; i < n; i++) {
    if (i > 0 && i % bs === 0) {
      const seal = jitter(cfg.sig.sign, rng, 0.18);
      const build = seal + bs * 0.004;
      cursor += build;
      blocks.push(makeBlock(blocks.length + 1, cursor, seal, build, p, cfg));
    }
    const sign = jitter(cfg.sig.sign, rng, 0.22);
    const verify = jitter(cfg.sig.verify, rng, 0.22);
    const e2e = sign + verify + TX.overheadMs * jitter(1, rng, 0.12);
    const start = cursor;
    cursor += e2e;
    txs.push({
      i, start, end: cursor, sign, verify, e2e,
      txBytes: p.txBytes, wireBytes: p.wireBytes,
    });
  }

  const seal = jitter(cfg.sig.sign, rng, 0.18);
  const build = seal + bs * 0.004;
  cursor += build;
  blocks.push(makeBlock(blocks.length + 1, cursor, seal, build, p, cfg));

  const chainVerifyMs = (n + blocks.length) * cfg.sig.verify + blocks.length * 0.03;
  const totalSimMs = cursor + chainVerifyMs;

  blocks.forEach((block, index) => {
    block.merkle = hashHex(`${cfg.sig.id}|merkle|${block.index}|${cfg.txCount}`);
    block.hash = hashHex(`${cfg.sig.id}|hash|${block.index}|${block.merkle}`);
    block.prev = index === 0 ? '0'.repeat(16) : blocks[index - 1].hash;
    block.sealHash = hashHex(`${cfg.sig.id}|seal|${block.index}|${block.sealMs}`);
  });

  return {
    cfg, proj: p, txs, blocks, totalSimMs, chainVerifyMs,
    sealDone: cursor,
    txShown: 0,
    blocksShown: 0,
    verifyStarted: false,
    logEvery: Math.max(1, Math.ceil(n / 12)),
    spawnEvery: Math.max(1, Math.floor(n / 24)),
    shownBlocks: new Set(),
  };
}

function makeBlock(index, sealedAt, sealMs, buildMs, p, cfg) {
  return {
    index,
    txCount: cfg.blockSize,
    bytes: p.blockBytes,
    share: p.share,
    sealedAt,
    sealMs,
    buildMs,
    sealBytes: cfg.sig.sig,
    tampered: false,
  };
}

/* ------------------------------------------------------------ run animation */
function startRun() {
  if (state.running) { cancelRun(); return; }

  const cfg = readConfig();
  resetStage(true);
  const plan = buildPlan(cfg);
  state.run = plan;
  state.running = true;
  state.tampered = false;

  setControlsDisabled(true);
  els.stage.classList.add('is-running');
  els.stage.classList.remove('is-done');
  els.runBtn.classList.add('is-running');
  els['run-icon'].textContent = '■';
  els['run-label'].textContent = 'Cancel run';
  setTopStatus('simulating…', 'busy');

  els['stage-sub'].textContent =
    `${cfg.sig.id} · ${cfg.kem.id} · ${cfg.txCount} tx in ${plan.blocks.length} block${plan.blocks.length === 1 ? '' : 's'}`;
  setPill(els['chain-pill'], 'live', `chain · 0/${plan.blocks.length} blocks`);
  setPill(els['session-pill'], 'ok', `session · ${fmtBytes(plan.proj.sessionBytes)}`);

  ['node-device', 'node-gateway', 'node-chain'].forEach(id => {
    const node = document.getElementById(id);
    node.classList.remove('is-active', 'is-done');
  });

  log(`handshake · ${cfg.kem.id} + ${cfg.sig.id} · ${fmtMs(plan.proj.handshakeMs)} · session ${fmtBytes(plan.proj.sessionBytes)}`, 'accent', 0);
  log(`device signs ${fmtBytes(cfg.sig.sig)} per tx · gateway seals every ${cfg.blockSize} tx`, '', 0);

  const duration = clamp((2500 + cfg.txCount * 10) / state.speed, 1700, 10000);
  const started = performance.now();

  const tick = now => {
    if (!state.running || state.run !== plan) return;
    const progress = Math.min(1, (now - started) / duration);
    const simTime = plan.totalSimMs * progress;
    updateRun(plan, simTime);
    updateProgress(plan, simTime, progress);
    if (progress < 1) {
      state.raf = requestAnimationFrame(tick);
    } else {
      finishRun(plan);
    }
  };
  state.raf = requestAnimationFrame(tick);
}

function updateRun(plan, simTime) {
  const { cfg, proj } = plan;

  while (plan.txShown < plan.txs.length && plan.txs[plan.txShown].end <= simTime) {
    const tx = plan.txs[plan.txShown];
    plan.txShown++;
    if (plan.txShown === 1 || plan.txShown % plan.logEvery === 0) {
      log(`tx #${String(plan.txShown).padStart(3, '0')} · sign ${fmtMsShort(tx.sign)} · ver ${fmtMsShort(tx.verify)} · ${Math.round(tx.txBytes)}B`, '', simTime);
    }
    if (plan.txShown % plan.spawnEvery === 0) spawnPacket('wire-1', '');
    pulseNode('node-device');
    pulseNode('node-gateway');
  }

  while (plan.blocksShown < plan.blocks.length && plan.blocks[plan.blocksShown].sealedAt <= simTime) {
    const block = plan.blocks[plan.blocksShown];
    plan.blocksShown++;
    addBlockCard(block);
    log(`block #${block.index} · ${block.txCount} tx · ${fmtBytes(block.bytes)} · ${block.share.toFixed(0)}% sig`, 'accent', simTime);
    spawnPacket('wire-2', 'amber');
    pulseNode('node-chain', true);
  }

  if (!plan.verifyStarted && simTime >= plan.sealDone) {
    plan.verifyStarted = true;
    setPill(els['chain-pill'], 'warn', 'chain · verifying');
    log(`validating ${plan.txs.length} sigs + ${plan.blocks.length} seals…`, 'warn', simTime);
  }

  const elapsed = plan.txShown ? plan.txs[plan.txShown - 1].end : 0;
  const throughput = elapsed > 0 ? plan.txShown / (elapsed / 1000) : 0;
  els['stat-throughput'].textContent = throughput > 0 ? fmtInt(throughput) : '—';

  const lastBlock = plan.blocksShown ? plan.blocks[plan.blocksShown - 1] : null;
  els['chain-sub'].textContent = `${plan.blocksShown} / ${plan.blocks.length} blocks`;
  els['chain-size'].textContent = lastBlock ? `${fmtBytes(lastBlock.bytes)} last` : `${fmtBytes(proj.blockBytes)} / block`;
  els['chain-share'].textContent = `${(lastBlock ? lastBlock.share : proj.share).toFixed(1)}% sig`;
  els['gw-seal'].textContent = lastBlock ? `${fmtMs(lastBlock.buildMs)} seal` : `${fmtMs(cfg.sig.sign)} seal`;

  if (plan.blocksShown) {
    setPill(els['chain-pill'], 'live', `chain · ${plan.blocksShown}/${plan.blocks.length} blocks`);
  }
}

function updateProgress(plan, simTime, progress) {
  els['progress-fill'].style.width = `${(progress * 100).toFixed(2)}%`;
  els['progress-label'].textContent = `${plan.txShown} / ${plan.txs.length} tx`;
  els['sim-clock'].textContent = `sim clock ${fmtClock(simTime)}`;
}

function finishRun(plan) {
  if (!state.running || state.run !== plan) return;
  state.running = false;
  cancelAnimationFrame(state.raf);

  updateRun(plan, plan.totalSimMs);
  updateProgress(plan, plan.totalSimMs, 1);

  els.stage.classList.remove('is-running');
  els.stage.classList.add('is-done');
  els.runBtn.classList.remove('is-running');
  els['run-icon'].textContent = '▶';
  els['run-label'].textContent = 'Run again';
  setControlsDisabled(false);
  setTopStatus('complete', '');

  setPill(els['chain-pill'], 'ok', 'chain · valid ✓');
  setPill(els['session-pill'], 'ok', `session · ${fmtBytes(plan.proj.sessionBytes)}`);
  els['stage-sub'].textContent =
    `${plan.txs.length} tx · ${plan.blocks.length} blocks · ${fmtClock(plan.totalSimMs)} simulated · ${state.speed}× playback`;

  els['stat-throughput'].textContent = fmtInt(plan.proj.throughput);
  els['chain-sub'].textContent = `${plan.blocks.length} blocks`;
  els['chain-size'].textContent = `${fmtBytes(plan.proj.blockBytes)} / block`;
  els['chain-share'].textContent = `${plan.proj.share.toFixed(1)}% sig`;

  log(`chain valid · ${plan.txs.length + plan.blocks.length} sigs verified in ${fmtMs(plan.chainVerifyMs)}`, 'ok', plan.totalSimMs);
  log(`complete · ${fmtInt(plan.proj.throughput)} tx/s projected · ${fmtClock(plan.totalSimMs)} sim`, 'ok', plan.totalSimMs);

  els['tamper-btn'].disabled = false;
  els['export-btn'].disabled = false;
  els['tamper-btn'].textContent = 'Tamper test';
  pulseNode('node-device', true);
  pulseNode('node-gateway', true);
  pulseNode('node-chain', true);
}

function cancelRun() {
  if (!state.running) return;
  cancelAnimationFrame(state.raf);
  state.running = false;
  state.run = null;
  state.tampered = false;
  clearPackets();
  els.stage.classList.remove('is-running', 'is-done');
  els.runBtn.classList.remove('is-running');
  els['run-icon'].textContent = '▶';
  els['run-label'].textContent = 'Run simulation';
  setControlsDisabled(false);
  setTopStatus('ready', '');
  ['node-device', 'node-gateway', 'node-chain'].forEach(id => {
    const node = document.getElementById(id);
    node.classList.remove('is-active', 'is-done');
  });
  clearLog('Run cancelled. Configuration is unchanged.');
  resetRunSurface();
  updateProjection();
  log('Simulator ready. Select a profile and run.', 'muted');
}

function resetStage(clear = true) {
  cancelAnimationFrame(state.raf);
  state.running = false;
  state.run = null;
  state.tampered = false;
  state.selectedBlock = null;
  clearPackets();
  resetRunSurface();
  els.stage.classList.remove('is-running', 'is-done');
  els.runBtn.classList.remove('is-running');
  els['run-icon'].textContent = '▶';
  els['run-label'].textContent = 'Run simulation';
  setTopStatus('ready', '');
  setControlsDisabled(false);
  if (clear) clearLog();
  updateProjection();
}

function resetRunSurface() {
  els['chain-view'].innerHTML = '<div class="empty">Blocks will appear here as the gateway seals them.</div>';
  els['inspector'].hidden = true;
  els['inspector'].innerHTML = '';
  els['chain-alert'].hidden = true;
  els['tamper-btn'].disabled = true;
  els['export-btn'].disabled = true;
  els['tamper-btn'].textContent = 'Tamper test';
  els['progress-fill'].style.width = '0%';
  els['progress-label'].textContent = '0 / 0 tx';
  els['sim-clock'].textContent = 'sim clock 0.000 s';
  setPill(els['chain-pill'], '', 'chain · idle');
}

function clearPackets() {
  state.packets.forEach(p => p.remove());
  state.packets.clear();
}

function setControlsDisabled(disabled) {
  ['kem-select', 'sig-select', 'tx-select', 'block-select'].forEach(id => {
    els[id].disabled = disabled;
  });
  $$('#speed-group button').forEach(btn => { btn.disabled = disabled; });
}

/* ------------------------------------------------------------------- blocks */
function addBlockCard(block) {
  const empty = els['chain-view'].querySelector('.empty');
  if (empty) empty.remove();

  const el = document.createElement('button');
  el.type = 'button';
  el.className = 'block';
  el.dataset.index = String(block.index);
  el.innerHTML = `
    <div class="block-top">
      <span class="block-idx">#${block.index}</span>
      <span class="block-tag">${block.txCount} tx</span>
    </div>
    <div class="block-hash">${block.hash}</div>
    <div class="block-metrics">
      <span>${fmtBytes(block.bytes)}</span>
      <span>${block.share.toFixed(0)}% sig</span>
    </div>
    <div class="block-bar"><i style="width:${block.share.toFixed(1)}%"></i></div>`;
  els['chain-view'].append(el);
  els['chain-view'].scrollLeft = els['chain-view'].scrollWidth;
}

function openInspector(block) {
  if (!block || !state.run) return;
  state.selectedBlock = block.index;
  $$('.block', els['chain-view']).forEach(card => {
    card.classList.toggle('is-selected', Number(card.dataset.index) === block.index);
  });
  const status = block.tampered
    ? '✗ invalid — payload byte flipped; Merkle root mismatch, transaction rejected'
    : '✓ valid — hash link, Merkle root, block seal and tx signatures accepted';
  els['inspector'].innerHTML = `
    <div class="inspector-head">
      <h3>Block #${block.index} · ${escapeHtml(state.run.cfg.sig.id)}</h3>
      <button type="button" class="icon-btn" data-close aria-label="Close inspector">×</button>
    </div>
    <div class="kv-grid">
      <div class="kv"><span>transactions</span><strong>${block.txCount}</strong></div>
      <div class="kv"><span>block bytes</span><strong>${fmtBytes(block.bytes)}</strong></div>
      <div class="kv"><span>signature share</span><strong>${block.share.toFixed(1)}%</strong></div>
      <div class="kv"><span>seal time</span><strong>${fmtMs(block.buildMs)}</strong></div>
    </div>
    <div class="hash-line"><span>prev</span><code>${block.prev}</code></div>
    <div class="hash-line"><span>merkle</span><code>${block.merkle}</code></div>
    <div class="hash-line"><span>seal</span><code>${block.sealHash}…</code></div>
    <p class="inspector-state ${block.tampered ? 'bad' : 'ok'}">${status}</p>`;
  els['inspector'].hidden = false;
}

/* ------------------------------------------------------------------- tamper */
function toggleTamper() {
  if (!state.run || !state.run.blocks.length) return;

  if (state.tampered) {
    state.run.blocks.forEach(block => { block.tampered = false; });
    state.tampered = false;
    $$('.block', els['chain-view']).forEach(card => {
      card.classList.remove('is-tampered');
      card.classList.remove('is-selected');
      const tag = card.querySelector('.block-tag');
      if (tag) tag.textContent = `${state.run.cfg.blockSize} tx`;
    });
    els['chain-alert'].hidden = true;
    els['tamper-btn'].textContent = 'Tamper test';
    setPill(els['chain-pill'], 'ok', 'chain · valid ✓');
    els['inspector'].hidden = true;
    log('chain restored · all Merkle roots and seals valid again', 'ok');
    return;
  }

  const block = state.run.blocks[state.run.blocks.length - 1];
  block.tampered = true;
  state.tampered = true;
  const card = els['chain-view'].querySelector(`.block[data-index="${block.index}"]`);
  if (card) {
    card.classList.add('is-tampered');
    const tag = card.querySelector('.block-tag');
    if (tag) tag.textContent = 'tampered';
  }
  els['chain-alert'].hidden = false;
  els['tamper-btn'].textContent = 'Reset chain';
  setPill(els['chain-pill'], 'bad', 'chain · INVALID');
  log(`tamper test · flipped a payload byte in block #${block.index} · Merkle root mismatch · chain rejected`, 'bad');
  openInspector(block);
}

/* ------------------------------------------------------------------- export */
function exportRun() {
  if (!state.run) return;
  const { cfg, proj, txs, blocks, totalSimMs, chainVerifyMs } = state.run;
  const payload = {
    schema: 'pqbench-sim/1',
    generated: new Date().toISOString(),
    note: 'Simulated run. Post-quantum parameters are a reference profile, not measurements from this device.',
    config: {
      kem: cfg.kem.id,
      signature: cfg.sig.id,
      tx_count: cfg.txCount,
      block_size: cfg.blockSize,
      playback_speed: state.speed,
    },
    projection: {
      tx_bytes: Math.round(proj.txBytes),
      wire_bytes: Math.round(proj.wireBytes),
      block_bytes: Math.round(proj.blockBytes),
      signature_share_pct: Number(proj.share.toFixed(3)),
      throughput_tx_s: Number(proj.throughput.toFixed(2)),
      session_setup_bytes: proj.sessionBytes,
      handshake_ms: Number(proj.handshakeMs.toFixed(4)),
    },
    simulated: {
      total_ms: Number(totalSimMs.toFixed(4)),
      chain_verify_ms: Number(chainVerifyMs.toFixed(4)),
      chain_valid: !state.tampered,
      tamper_detected: state.tampered,
      transactions: txs.map(tx => ({
        seq: tx.i,
        sign_ms: Number(tx.sign.toFixed(6)),
        verify_ms: Number(tx.verify.toFixed(6)),
        e2e_ms: Number(tx.e2e.toFixed(6)),
        tx_bytes: Math.round(tx.txBytes),
      })),
      blocks: blocks.map(block => ({
        index: block.index,
        tx_count: block.txCount,
        bytes: Math.round(block.bytes),
        signature_share_pct: Number(block.share.toFixed(3)),
        seal_ms: Number(block.buildMs.toFixed(6)),
        hash: block.hash,
        merkle_root: block.merkle,
        prev_hash: block.prev,
        tampered: block.tampered,
      })),
    },
  };

  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `pqbench-sim-${cfg.sig.id}-${cfg.kem.id}.json`;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  log('run exported as JSON', 'ok');
}

/* ==========================================================================
   Benchmark lab
   ========================================================================== */

function sampleOp(base, n, key) {
  const rng = mulberry32(hashStr(`${key}|${n}`));
  const samples = [];
  for (let i = 0; i < n; i++) {
    const gauss = (rng() + rng() + rng() + rng() - 2) / 1.1547;
    samples.push(base * Math.exp(gauss * 0.2));
  }
  samples.sort((a, b) => a - b);
  const at = q => samples[Math.floor((n - 1) * q)];
  return { median: at(0.5), p95: at(0.95), n };
}

function benchSigRow(result) {
  const { alg } = result;
  const p = projection({ kem: KEMS[0], sig: alg, txCount: 120, blockSize: 20 });
  const family = alg.family === 'classical' ? 'classical' : 'post-quantum';
  return `<tr class="${alg.family === 'classical' ? 'is-classical' : ''}">
    <td><div class="alg-name">${escapeHtml(alg.id)}</div><div class="alg-sub">${escapeHtml(alg.blurb)}</div></td>
    <td><span class="tag ${alg.family}">${family}</span></td>
    <td class="num">${fmtMs(result.keygen.median)}<em>${fmtMs(result.keygen.p95)}</em></td>
    <td class="num">${fmtMs(result.sign.median)}<em>${fmtMs(result.sign.p95)}</em></td>
    <td class="num">${fmtMs(result.verify.median)}<em>${fmtMs(result.verify.p95)}</em></td>
    <td class="num">${fmtBytes(alg.pk)}</td>
    <td class="num">${fmtBytes(alg.sig)}</td>
    <td class="num">${fmtInt(p.throughput)}</td>
    <td class="num">${p.share.toFixed(1)}%</td>
    <td><span class="tag ${alg.measured ? 'measured' : 'ref'}">${alg.measured ? 'measured' : 'reference'}</span></td>
  </tr>`;
}

function benchKemRow(result) {
  const { alg } = result;
  const family = alg.family === 'classical' ? 'classical' : 'post-quantum';
  return `<tr class="${alg.family === 'classical' ? 'is-classical' : ''}">
    <td><div class="alg-name">${escapeHtml(alg.id)}</div><div class="alg-sub">${escapeHtml(alg.blurb)}</div></td>
    <td><span class="tag ${alg.family}">${family}</span></td>
    <td class="num">${fmtMs(result.keygen.median)}<em>${fmtMs(result.keygen.p95)}</em></td>
    <td class="num">${fmtMs(result.encaps.median)}<em>${fmtMs(result.encaps.p95)}</em></td>
    <td class="num">${fmtMs(result.decaps.median)}<em>${fmtMs(result.decaps.p95)}</em></td>
    <td class="num">${fmtBytes(alg.pk)}</td>
    <td class="num">${fmtBytes(alg.ct)}</td>
    <td class="num">${alg.ss} B</td>
    <td class="num">${fmtBytes(alg.pk + alg.ct)}</td>
  </tr>`;
}

function renderSigTable(rows) {
  const body = els['sig-table-body'];
  if (!rows || !rows.length) {
    body.innerHTML = '<tr class="placeholder-row"><td colspan="10">Run the benchmark to populate this table.</td></tr>';
    return;
  }
  body.innerHTML = rows.map(benchSigRow).join('');
}

function renderKemTable(rows) {
  const body = els['kem-table-body'];
  if (!rows || !rows.length) {
    body.innerHTML = '<tr class="placeholder-row"><td colspan="9">Run the benchmark to populate this table.</td></tr>';
    return;
  }
  body.innerHTML = rows.map(benchKemRow).join('');
}

async function runBenchmark() {
  if (state.bench.running) return;
  state.bench.running = true;
  state.bench.started = true;

  const btn = els['bench-btn'];
  const label = els['bench-btn-label'];
  const n = parseInt(els['samples-select'].value, 10) || 200;
  btn.disabled = true;
  label.textContent = 'Benchmarking…';
  els['bench-badge'].textContent = 'running';
  els['bench-badge'].className = 'badge warn';
  els['bench-status'].textContent = 'warming up…';
  els['bench-progress'].style.width = '0%';
  setTopStatus('benchmarking…', 'busy');

  const sigResults = [];
  const kemResults = [];
  const total = SIGS.length + KEMS.length;
  let done = 0;

  await sleep(180);

  for (const alg of SIGS) {
    els['bench-status'].textContent = `${alg.id} · ${done + 1}/${total}`;
    sigResults.push({
      alg,
      keygen: sampleOp(alg.keygen, n, `${alg.id}|keygen`),
      sign: sampleOp(alg.sign, n, `${alg.id}|sign`),
      verify: sampleOp(alg.verify, n, `${alg.id}|verify`),
    });
    renderSigTable(sigResults);
    done++;
    els['bench-progress'].style.width = `${(done / total) * 100}%`;
    await sleep(120);
  }

  for (const alg of KEMS) {
    els['bench-status'].textContent = `${alg.id} · ${done + 1}/${total}`;
    kemResults.push({
      alg,
      keygen: sampleOp(alg.keygen, n, `${alg.id}|keygen`),
      encaps: sampleOp(alg.encaps, n, `${alg.id}|encaps`),
      decaps: sampleOp(alg.decaps, n, `${alg.id}|decaps`),
    });
    renderKemTable(kemResults);
    done++;
    els['bench-progress'].style.width = `${(done / total) * 100}%`;
    await sleep(120);
  }

  state.bench = { done: true, running: false, sigs: sigResults, kems: kemResults, n, started: true };

  els['bench-progress'].style.width = '100%';
  els['bench-status'].textContent = `complete · ${SIGS.length} signatures + ${KEMS.length} KEMs · ${n} samples/op`;
  els['bench-badge'].textContent = `${n} samples`;
  els['bench-badge'].className = 'badge ok';
  els['sig-table-badge'].textContent = `${sigResults.length} schemes`;
  els['kem-table-badge'].textContent = `${kemResults.length} schemes`;
  btn.disabled = false;
  label.textContent = 'Run benchmark';
  setTopStatus('benchmark complete', '');
  fillBenchSummary();
  renderTables();
  if (state.view === 'bench') requestAnimationFrame(renderCharts);
}

function fillBenchSummary() {
  const rows = state.bench.sigs;
  if (!rows || !rows.length) return;

  const fastestSign = rows.reduce((a, b) => (b.sign.median < a.sign.median ? b : a));
  const pq = rows.filter(r => r.alg.family === 'pq');
  const fastestPQVerify = pq.reduce((a, b) => (b.verify.median < a.verify.median ? b : a));
  const smallestPQSig = pq.reduce((a, b) => (b.alg.sig < a.alg.sig ? b : a));
  const largestSig = rows.reduce((a, b) => (b.alg.sig > a.alg.sig ? b : a));

  els['bench-fastest-sign'].textContent = fastestSign.alg.id;
  els['bench-fastest-sign-sub'].textContent = `${fmtMs(fastestSign.sign.median)} median sign`;
  els['bench-fastest-verify'].textContent = fastestPQVerify.alg.id;
  els['bench-fastest-verify-sub'].textContent = `${fmtMs(fastestPQVerify.verify.median)} median verify`;
  els['bench-smallest-sig'].textContent = smallestPQSig.alg.id;
  els['bench-smallest-sig-sub'].textContent = `${fmtBytes(smallestPQSig.alg.sig)} signature`;
  els['bench-largest-sig'].textContent = largestSig.alg.id;
  els['bench-largest-sig-sub'].textContent = `${fmtBytes(largestSig.alg.sig)} signature`;
}

function renderTables() {
  if (!state.bench.done) return;
  renderSigTable(state.bench.sigs);
  renderKemTable(state.bench.kems);
}

/* ------------------------------------------------------------------- charts */
function roundRect(ctx, x, y, w, h, r) {
  const rr = Math.min(r, Math.abs(w) / 2, Math.abs(h) / 2);
  ctx.beginPath();
  ctx.moveTo(x + rr, y);
  ctx.arcTo(x + w, y, x + w, y + h, rr);
  ctx.arcTo(x + w, y + h, x, y + h, rr);
  ctx.arcTo(x, y + h, x, y, rr);
  ctx.arcTo(x, y, x + w, y, rr);
  ctx.closePath();
}

function fmtAxis(value, unit) {
  return unit === 'ms' ? fmtMsShort(value) : fmtBytes(value);
}

function shortLabel(label) {
  const short = label.replace('SLH-DSA-SHAKE-', 'SLH-');
  return short.length > 19 ? `${short.slice(0, 18)}…` : short;
}

function drawEmptyChart(canvas) {
  const width = canvas.clientWidth;
  if (width < 40) return;
  const height = 408;
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  canvas.width = Math.round(width * dpr);
  canvas.height = Math.round(height * dpr);
  canvas.style.height = `${height}px`;
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, width, height);

  ctx.strokeStyle = 'rgba(148,177,204,0.16)';
  ctx.lineWidth = 1;
  ctx.setLineDash([5, 7]);
  roundRect(ctx, 18, 28, width - 36, height - 56, 12);
  ctx.stroke();
  ctx.setLineDash([]);

  ctx.fillStyle = '#52657f';
  ctx.font = `10px ${MONO}`;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText('Run the benchmark to populate this chart', width / 2, height / 2);
}

function drawBars(canvas, groups, series, opts) {
  if (!canvas) return;
  const width = canvas.clientWidth;
  if (width < 40) return;

  const height = 66 + groups.length * 42;
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  canvas.width = Math.round(width * dpr);
  canvas.height = Math.round(height * dpr);
  canvas.style.height = `${height}px`;
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, width, height);

  if (!groups.length) { drawEmptyChart(canvas); return; }

  const left = Math.max(90, Math.min(148, width * 0.27));
  const right = 62;
  const top = 44;
  const bottom = 31;
  const plotW = Math.max(40, width - left - right);
  const plotH = height - top - bottom;
  const rowH = plotH / groups.length;
  const barH = Math.max(7, Math.min(13, rowH * 0.29));
  const barGap = 4;

  const values = [];
  groups.forEach(group => series.forEach(s => {
    const value = group.values[s.key];
    if (value > 0 && isFinite(value)) values.push(value);
  }));
  if (!values.length) { drawEmptyChart(canvas); return; }

  const minValue = Math.min(...values);
  const maxValue = Math.max(...values);
  const lo = Math.pow(10, Math.floor(Math.log10(minValue)) - 0.06);
  const hi = Math.pow(10, Math.ceil(Math.log10(maxValue)) + 0.06);
  const l0 = Math.log10(lo);
  const l1 = Math.log10(hi);
  const xFor = value => left + ((Math.log10(value) - l0) / (l1 - l0)) * plotW;

  // Row tints and labels
  groups.forEach((group, index) => {
    const rowTop = top + index * rowH;
    if (group.family === 'classical') {
      ctx.fillStyle = 'rgba(77,226,255,0.05)';
      ctx.fillRect(left, rowTop + 1, plotW, rowH - 2);
    }
    ctx.font = `10px ${MONO}`;
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    ctx.fillStyle = group.family === 'classical' ? '#8cefff' : '#b8c5d9';
    ctx.fillText(shortLabel(group.label), left - 10, rowTop + rowH / 2);
  });

  // Grid ticks
  const ticks = [];
  for (let e = Math.ceil(l0); e <= Math.floor(l1); e++) {
    for (const m of [1, 2, 5]) {
      const value = m * Math.pow(10, e);
      if (value >= lo && value <= hi) ticks.push(value);
    }
  }
  ctx.font = `8.5px ${MONO}`;
  ticks.forEach(value => {
    const x = xFor(value);
    const major = Math.abs(Math.log10(value) - Math.round(Math.log10(value))) < 1e-6;
    ctx.strokeStyle = major ? 'rgba(148,177,204,0.09)' : 'rgba(148,177,204,0.035)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(Math.round(x) + 0.5, top - 6);
    ctx.lineTo(Math.round(x) + 0.5, top + plotH);
    ctx.stroke();
    if (!major) return;
    ctx.fillStyle = '#52657f';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    ctx.fillText(fmtAxis(value, opts.unit), x, top + plotH + 7);
  });

  // Baseline
  ctx.strokeStyle = 'rgba(148,177,204,0.18)';
  ctx.beginPath();
  ctx.moveTo(left, top + plotH + 0.5);
  ctx.lineTo(left + plotW, top + plotH + 0.5);
  ctx.stroke();

  // Bars
  groups.forEach((group, index) => {
    const rowTop = top + index * rowH;
    const totalH = series.length * barH + (series.length - 1) * barGap;
    let y = rowTop + (rowH - totalH) / 2;

    series.forEach(s => {
      const value = group.values[s.key];
      if (!(value > 0) || !isFinite(value)) return;
      const barW = Math.max(1.5, xFor(value) - left);
      ctx.fillStyle = s.color;
      roundRect(ctx, left, y, Math.min(barW, plotW), barH, 3);
      ctx.fill();

      const label = fmtAxis(value, opts.unit);
      ctx.font = `8.5px ${MONO}`;
      ctx.textAlign = 'left';
      ctx.textBaseline = 'middle';
      ctx.fillStyle = '#7e90a8';
      const labelX = left + barW + 6;
      if (labelX + ctx.measureText(label).width < width - 3) {
        ctx.fillText(label, labelX, y + barH / 2);
      }
      y += barH + barGap;
    });
  });

  // Legend
  let legendX = left;
  const legendY = 20;
  ctx.font = `9px ${MONO}`;
  series.forEach(s => {
    ctx.fillStyle = s.color;
    roundRect(ctx, legendX, legendY - 4, 10, 8, 2);
    ctx.fill();
    ctx.fillStyle = '#8fa1ba';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'middle';
    ctx.fillText(s.label, legendX + 15, legendY);
    legendX += 15 + ctx.measureText(s.label).width + 20;
  });

  ctx.textAlign = 'right';
  ctx.fillStyle = '#45566e';
  ctx.fillText(opts.unit === 'ms' ? 'latency (ms, log)' : 'bytes (log)', width - 2, 20);
}

function renderCharts() {
  if (!state.bench.done) {
    drawEmptyChart(els['chart-latency']);
    drawEmptyChart(els['chart-size']);
    return;
  }

  const sigGroups = state.bench.sigs.map(row => ({
    label: row.alg.id,
    family: row.alg.family,
    values: { sign: row.sign.median, verify: row.verify.median },
  }));
  drawBars(els['chart-latency'], sigGroups, [
    { key: 'sign', label: 'sign', color: '#4de2ff' },
    { key: 'verify', label: 'verify', color: '#a78bfa' },
  ], { unit: 'ms' });

  const sizeGroups = state.bench.sigs.map(row => ({
    label: row.alg.id,
    family: row.alg.family,
    values: { pk: row.alg.pk, sig: row.alg.sig },
  }));
  drawBars(els['chart-size'], sizeGroups, [
    { key: 'pk', label: 'public key', color: '#4de2ff' },
    { key: 'sig', label: 'signature', color: '#f5b942' },
  ], { unit: 'B' });
}

/* -------------------------------------------------------------------- views */
function showView(name, updateHash = true) {
  if (!['sim', 'bench', 'method'].includes(name)) name = 'sim';
  state.view = name;

  $$('.view').forEach(view => {
    const active = view.id === `view-${name}`;
    view.classList.toggle('is-active', active);
    view.hidden = !active;
  });
  $$('.tab').forEach(tab => {
    const active = tab.dataset.view === name;
    tab.classList.toggle('is-active', active);
    tab.setAttribute('aria-selected', String(active));
  });

  if (updateHash && location.hash !== `#${name}`) {
    history.replaceState(null, '', `#${name}`);
  }

  if (name === 'bench') {
    if (!state.bench.done && !state.bench.running) {
      setTimeout(() => {
        if (state.view === 'bench' && !state.bench.done && !state.bench.running) runBenchmark();
      }, 350);
    } else if (state.bench.done) {
      requestAnimationFrame(() => requestAnimationFrame(renderCharts));
    }
  }
}

/* --------------------------------------------------------------- boot & events */
function bindEvents() {
  $$('.tab').forEach(tab => {
    tab.addEventListener('click', () => showView(tab.dataset.view));
  });

  window.addEventListener('hashchange', () => {
    const name = location.hash.replace('#', '');
    if (['sim', 'bench', 'method'].includes(name)) showView(name, false);
  });

  ['kem-select', 'sig-select', 'tx-select', 'block-select'].forEach(id => {
    els[id].addEventListener('change', () => {
      if (state.running) return;
      updateProjection();
      if (state.run) {
        resetStage(false);
        log('Configuration changed. Run the simulation to rebuild the chain.', 'muted');
      }
    });
  });

  $$('#speed-group button').forEach(btn => {
    btn.addEventListener('click', () => {
      if (state.running) return;
      state.speed = Number(btn.dataset.speed) || 2;
      $$('#speed-group button').forEach(b => b.classList.toggle('is-active', b === btn));
      updateProjection();
    });
  });

  els['run-btn'].addEventListener('click', () => {
    if (state.running) cancelRun();
    else startRun();
  });

  els['chain-view'].addEventListener('click', event => {
    const card = event.target.closest('.block');
    if (!card || !state.run) return;
    const block = state.run.blocks.find(b => b.index === Number(card.dataset.index));
    if (block) openInspector(block);
  });

  els['inspector'].addEventListener('click', event => {
    if (!event.target.closest('[data-close]')) return;
    els['inspector'].hidden = true;
    $$('.block', els['chain-view']).forEach(card => card.classList.remove('is-selected'));
  });

  els['tamper-btn'].addEventListener('click', toggleTamper);
  els['export-btn'].addEventListener('click', exportRun);
  els['bench-btn'].addEventListener('click', runBenchmark);

  els['samples-select'].addEventListener('change', () => {
    if (!state.bench.running && state.bench.done) {
      els['bench-status'].textContent = 'sample size changed · rerun to apply';
      els['bench-badge'].textContent = 'stale';
      els['bench-badge'].className = 'badge warn';
    }
  });

  let resizeTimer;
  window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => {
      if (state.view === 'bench') renderCharts();
    }, 180);
  });
}

function boot() {
  cacheEls();
  initSelects();
  bindEvents();
  updateProjection();
  renderCharts();

  const initial = location.hash.replace('#', '');
  showView(['sim', 'bench', 'method'].includes(initial) ? initial : 'sim', false);

  if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    // Keep behaviour identical; CSS already disables the visual animation.
  }
}

boot();
