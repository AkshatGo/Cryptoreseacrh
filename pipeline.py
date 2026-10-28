"""
pipeline.py - Layer 2: an end-to-end device -> gateway -> blockchain flow.

Two SEPARATE OS processes talk over a real TCP socket (loopback):

  DEVICE  : key exchange (KEM) -> derive session key -> for each reading:
            build 100-byte payload, SIGN it, encrypt (AES-256-GCM), send, wait for ack
  GATEWAY : KEM decapsulate -> derive same key -> for each frame: decrypt, VERIFY signature,
            pool it; every B transactions build a BLOCK (Merkle root + header) and SEAL it
            with the gateway's signature (authority-style sealing, no Proof-of-Work).
  Then the chain is re-validated end to end (hash links, Merkle roots, seals, every tx signature)
  and a tamper test confirms modified data is detected.

Why no Proof-of-Work: the base paper itself says PoW is unsuitable for IoT (energy cost) and points
to lightweight authority-style consensus. Also, in real PoW chains only the small block HEADER is
hashed per attempt, so signature size does not change mining cost; it changes block size and
verification cost, which is what we measure.

Everything is measured; nothing is simulated by formula. The only derived columns (documented in
the report) are simple arithmetic on measured byte counts.
"""
import argparse, hashlib, multiprocessing as mp, os, socket, struct, sys, time, traceback
import algos
from common import ensure_results, raise_priority, save_json, write_csv, RESULTS

HDR = ">Q32s32sQI"                 # index, prev_hash, merkle_root, timestamp, n_tx  (84 bytes)
PAYLOAD_LEN = 100
sha256 = lambda b: hashlib.sha256(b).digest()


# ----------------------------------------------------------------- framing
def send_frame(sock, data):
    sock.sendall(struct.pack(">I", len(data)) + data)


def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed")
        buf += chunk
    return bytes(buf)


def recv_frame(sock):
    (n,) = struct.unpack(">I", _recv_exact(sock, 4))
    return _recv_exact(sock, n)


# ------------------------------------------------------------- crypto glue
def derive_key(shared_secret):
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"pqbench-session").derive(shared_secret)


def merkle_root(hashes_):
    if not hashes_:
        return b"\x00" * 32
    level = list(hashes_)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def split_tx(tx):
    payload = tx[:PAYLOAD_LEN]
    (slen,) = struct.unpack(">H", tx[PAYLOAD_LEN:PAYLOAD_LEN + 2])
    return payload, tx[PAYLOAD_LEN + 2:PAYLOAD_LEN + 2 + slen]


def validate_chain(chain, gw_pk, dev_pk, sig):
    prev = chain[0]["header_hash"]
    for blk in chain[1:]:
        _, prev_hash, root, _, n = struct.unpack(HDR, blk["header"])
        hh = sha256(blk["header"])
        if prev_hash != prev or n != len(blk["txs"]):
            return False
        if not sig.verify(gw_pk, hh, blk["seal"]):
            return False
        if merkle_root([sha256(t) for t in blk["txs"]]) != root:
            return False
        for t in blk["txs"]:
            payload, s = split_tx(t)
            if not sig.verify(dev_pk, payload, s):
                return False
        prev = hh
    return True


def _lookup(kem_name, sig_name):
    return dict(algos.kem_catalog())[kem_name](), dict(algos.sig_catalog(True))[sig_name]()


# ------------------------------------------------------------------ gateway
def gateway_main(cfg, q_port, q_res):
    try:
        raise_priority()
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        kem, sig = _lookup(cfg["kem"], cfg["sig"])
        t0 = time.perf_counter_ns()
        kem_pk = kem.keygen()
        gw_pk = sig.keygen()
        setup_ns = time.perf_counter_ns() - t0

        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
        q_port.put(srv.getsockname()[1])
        conn, _ = srv.accept()
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        send_frame(conn, kem_pk)
        ct = recv_frame(conn)
        t0 = time.perf_counter_ns(); ss = kem.decaps(ct); decaps_ns = time.perf_counter_ns() - t0
        aes = AESGCM(derive_key(ss))
        dev_pk = recv_frame(conn)
        send_frame(conn, b"R")

        genesis_hdr = struct.pack(HDR, 0, b"\x00" * 32, b"\x00" * 32, 0, 0)
        chain = [{"header": genesis_hdr, "header_hash": sha256(genesis_hdr), "seal": b"", "txs": []}]
        pool, verify_ns, build_ns, blk_rows, sig_len, bad = [], [], [], [], [], 0

        while True:
            frame = recv_frame(conn)
            if frame == b"END":
                break
            tx = aes.decrypt(frame[:12], frame[12:], None)
            payload, s = split_tx(tx)
            t0 = time.perf_counter_ns(); ok = sig.verify(dev_pk, payload, s); verify_ns.append(time.perf_counter_ns() - t0)
            if not ok:
                bad += 1
            else:
                pool.append(tx); sig_len.append(len(s))
            conn.sendall(struct.pack(">I", 1) + b"\x01")
            if len(pool) == cfg["block_size"]:
                t0 = time.perf_counter_ns()
                root = merkle_root([sha256(t) for t in pool])
                hdr = struct.pack(HDR, len(chain), chain[-1]["header_hash"], root, time.time_ns(), len(pool))
                hh = sha256(hdr)
                seal = sig.sign(hh)
                build_ns.append(time.perf_counter_ns() - t0)
                chain.append({"header": hdr, "header_hash": hh, "seal": seal, "txs": pool})
                size = len(hdr) + 2 + len(seal) + sum(len(t) for t in pool)
                sbytes = sum(len(split_tx(t)[1]) for t in pool) + len(seal)
                blk_rows.append((len(chain) - 1, build_ns[-1], size, sbytes))
                pool = []

        t0 = time.perf_counter_ns(); valid = validate_chain(chain, gw_pk, dev_pk, sig); chain_ns = time.perf_counter_ns() - t0

        # tamper tests (not timed): the chain must reject modified data
        detected = []
        if len(chain) > 1:
            import copy
            c1 = copy.deepcopy(chain)
            t = bytearray(c1[1]["txs"][0]); t[50] ^= 0xFF; c1[1]["txs"][0] = bytes(t)
            detected.append(not validate_chain(c1, gw_pk, dev_pk, sig))
            c2 = copy.deepcopy(chain)
            sl = bytearray(c2[1]["seal"]); sl[len(sl) // 2] ^= 0xFF; c2[1]["seal"] = bytes(sl)
            detected.append(not validate_chain(c2, gw_pk, dev_pk, sig))

        q_res.put({"role": "gateway", "setup_ns": setup_ns, "decaps_ns": decaps_ns, "verify_ns": verify_ns,
                   "build_ns": build_ns, "blocks": blk_rows, "chain_ns": chain_ns, "chain_valid": valid,
                   "tamper_detected": bool(detected) and all(detected), "bad_sigs": bad,
                   "kem_pk": len(kem_pk), "ct": len(ct), "dev_pk": len(dev_pk), "gw_pk": len(gw_pk),
                   "n_blocks": len(chain) - 1})
    except BaseException:
        q_res.put({"role": "gateway", "error": traceback.format_exc()})


# ------------------------------------------------------------------- device
def device_main(cfg, port, q_res):
    try:
        raise_priority()
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        kem, sig = _lookup(cfg["kem"], cfg["sig"])
        dev_pk = sig.keygen()
        s = socket.socket(); s.connect(("127.0.0.1", port))
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        t_hs = time.perf_counter_ns()
        kem_pk = recv_frame(s)
        t0 = time.perf_counter_ns(); ct, ss = kem.encaps(kem_pk); encaps_ns = time.perf_counter_ns() - t0
        aes = AESGCM(derive_key(ss))
        send_frame(s, ct); send_frame(s, dev_pk)
        recv_frame(s)
        handshake_ns = time.perf_counter_ns() - t_hs

        sign_ns, e2e_ns, tx_len, wire_len, sig_len = [], [], [], [], []
        wall0 = time.perf_counter_ns()
        for seq in range(cfg["n_tx"]):
            t_start = time.perf_counter_ns()
            reading = (sha256(struct.pack(">I", seq)) * 3)[:PAYLOAD_LEN - 16]
            payload = struct.pack(">IIQ", 1, seq, time.time_ns()) + reading
            t0 = time.perf_counter_ns(); sg = sig.sign(payload); sign_ns.append(time.perf_counter_ns() - t0)
            tx = payload + struct.pack(">H", len(sg)) + sg
            nonce = struct.pack(">IQ", 0, seq)
            frame = nonce + aes.encrypt(nonce, tx, None)
            send_frame(s, frame)
            recv_frame(s)
            e2e_ns.append(time.perf_counter_ns() - t_start)
            tx_len.append(len(tx)); wire_len.append(len(frame)); sig_len.append(len(sg))
        wall_ns = time.perf_counter_ns() - wall0
        send_frame(s, b"END")
        q_res.put({"role": "device", "encaps_ns": encaps_ns, "handshake_ns": handshake_ns, "sign_ns": sign_ns,
                   "e2e_ns": e2e_ns, "tx_len": tx_len, "wire_len": wire_len, "sig_len": sig_len, "wall_ns": wall_ns})
    except BaseException:
        q_res.put({"role": "device", "error": traceback.format_exc()})


# ------------------------------------------------------------ orchestration
def run_once(cfg, timeout_s):
    ctx = mp.get_context("spawn")
    q_port, q_res = ctx.Queue(), ctx.Queue()
    gw = ctx.Process(target=gateway_main, args=(cfg, q_port, q_res)); gw.start()
    try:
        port = q_port.get(timeout=120)
    except Exception:
        gw.terminate(); raise RuntimeError("gateway did not start (see error from gateway above, if any)")
    dev = ctx.Process(target=device_main, args=(cfg, port, q_res)); dev.start()
    out = {}
    t_end = time.time() + timeout_s
    while len(out) < 2 and time.time() < t_end:
        try:
            r = q_res.get(timeout=2)
            out[r["role"]] = r
        except Exception:
            if not (gw.is_alive() or dev.is_alive()) and len(out) < 2 and q_res.empty():
                break
    for p in (dev, gw):
        p.join(timeout=10)
        if p.is_alive():
            p.terminate()
    for role in ("device", "gateway"):
        if role not in out:
            raise RuntimeError(f"{role} produced no result (timeout?)")
        if "error" in out[role]:
            raise RuntimeError(f"{role} failed:\n{out[role]['error']}")
    return out["device"], out["gateway"]


def run_all(runs, n_tx, block_size, include_slow, only=None):
    ensure_results()
    runs_rows, tx_rows, blk_rows = [], [], []
    for label, kem, sig in algos.pipeline_pairs(include_slow):
        if only and label not in only:
            continue
        slow = algos.is_slow(sig)
        cfg = {"kem": kem, "sig": sig, "n_tx": min(n_tx, 20) if slow else n_tx,
               "block_size": 10 if slow else block_size}
        cfg["n_tx"] -= cfg["n_tx"] % cfg["block_size"]
        print(f"[PIPE] {label}: {cfg['n_tx']} tx/run, block={cfg['block_size']}, runs={runs}", flush=True)
        for r in range(runs):
            dev, gw = run_once(cfg, timeout_s=60 + cfg["n_tx"] * (4 if slow else 0.5))
            n = cfg["n_tx"]
            runs_rows.append((label, kem, sig, r, n, cfg["block_size"], gw["n_blocks"],
                              gw["kem_pk"] + gw["ct"] + gw["dev_pk"], dev["handshake_ns"], dev["encaps_ns"],
                              gw["decaps_ns"], dev["wall_ns"], gw["chain_ns"], int(gw["chain_valid"]),
                              int(gw["tamper_detected"]), gw["bad_sigs"], gw["kem_pk"], gw["ct"], gw["dev_pk"], gw["gw_pk"]))
            for i in range(n):
                tx_rows.append((label, r, i, dev["sign_ns"][i], gw["verify_ns"][i], dev["e2e_ns"][i],
                                dev["tx_len"][i], dev["wire_len"][i], dev["sig_len"][i]))
            for (b, bns, bsize, sbytes) in gw["blocks"]:
                blk_rows.append((label, r, b, bns, bsize, sbytes))
            ok = "OK" if gw["chain_valid"] and gw["tamper_detected"] else "CHECK!"
            print(f"    run {r + 1}/{runs}: chain valid={gw['chain_valid']} tamper detected={gw['tamper_detected']} [{ok}] "
                  f"{n / (dev['wall_ns'] / 1e9):.0f} tx/s", flush=True)
            time.sleep(0.5)
    write_csv(os.path.join(RESULTS, "pipeline_runs.csv"),
              ["config", "kem", "sig", "run", "n_tx", "block_size", "n_blocks", "session_setup_bytes", "handshake_ns",
               "encaps_ns", "decaps_ns", "device_wall_ns", "chain_verify_ns", "chain_valid", "tamper_detected",
               "bad_sigs", "kem_pk_B", "kem_ct_B", "dev_sig_pk_B", "gw_sig_pk_B"], runs_rows)
    write_csv(os.path.join(RESULTS, "pipeline_tx.csv"),
              ["config", "run", "seq", "sign_ns", "verify_ns", "e2e_ns", "tx_bytes", "wire_bytes", "sig_bytes"], tx_rows)
    write_csv(os.path.join(RESULTS, "pipeline_blocks.csv"),
              ["config", "run", "block", "build_ns", "block_bytes", "sig_bytes_in_block"], blk_rows)
    print("Saved pipeline_runs.csv, pipeline_tx.csv, pipeline_blocks.csv")


if __name__ == "__main__":
    mp.freeze_support()
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--no-slow", action="store_true")
    ap.add_argument("--only", nargs="*")
    a = ap.parse_args()
    runs, n_tx = (2, 40) if a.quick else (5, 200)
    t0 = time.time()
    run_all(runs, n_tx, 20, not a.no_slow, a.only)
    print(f"Done in {time.time() - t0:.0f}s")
