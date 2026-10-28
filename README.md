# pqbench - classical vs post-quantum cryptography, measured on one device

Everything in the final tables is produced by these scripts from raw logs. Nothing is typed by hand.

## What it measures

| Layer | Script | What happens |
|---|---|---|
| 1. Primitives | `bench_primitives.py` | Key generation, sign/verify, encaps/decaps for ECDH/ECDSA (P-256), ML-KEM-512/768/1024, ML-DSA-44/65/87, Falcon-512/1024, SLH-DSA-SHAKE-128f and 128s for the Windows simulation. The SHA2-128f backend is excluded because the installed Windows liboqs build fails its valid-signature self-test. Each operation is timed separately, many times, with warm-up discarded. |
| 2. Pipeline | `pipeline.py` | A DEVICE process and a GATEWAY process talk over a real TCP socket: KEM key exchange, AES-256-GCM channel, signed 100-byte sensor transactions, blocks (Merkle root + header) sealed by the gateway's signature, full chain validation, and a tamper test. Measures transaction/block sizes, latency, throughput, chain verification time. |
| Report | `make_report.py` | Builds Tables A, B1, B2, C, D plus charts from the raw CSVs. |

## Run it (Windows, your HP Victus)

1. Plug in the charger. Set Windows power mode to **Best performance**. Close browsers and other apps. Turn off sleep.
2. Open PowerShell in this folder.
3. Install (liboqs is already built on your machine from earlier):
   ```
   pip install -r requirements.txt
   pip install psutil matplotlib
   ```
   (`psutil` and `matplotlib` are optional. If either fails to install on Python 3.14, skip it. You only lose system details / charts.)
4. Smoke test first (a few minutes):
   ```
   python run_all.py --quick
   ```
5. Full run (roughly 10-25 minutes). **Do not use the laptop while it runs:**
   ```
   python run_all.py
   ```
   Add `--no-slow` to skip the slowest scheme (SLH-DSA-128s) if time is short.
6. Open `results\REPORT.md`. Charts are in `results\charts\`. Raw data is in the CSV files.

For repeatability, run the full measurement a second time on another day and keep both `results` folders.

## What the numbers mean (and don't)

- Real measurements on a general-purpose x86 laptop, same method for every algorithm.
- Not absolute numbers for constrained IoT hardware. Use the ratios and rankings, not the milliseconds, when talking about IoT.
- The pipeline runs over loopback, so it does not capture real network latency.
- No Proof-of-Work: blocks are sealed by an authority signature. The base paper itself says PoW is unsuitable for IoT.
- Peak memory is not reported (Python cannot measure native-library memory reliably). Exact key/signature sizes are reported instead.
- Message and transaction payloads are fixed at 100 bytes so every algorithm signs identical data.

## Method rules that make it fair

- Key generation, signing and verification are timed separately; library objects are created once, outside the timing loop.
- Every operation takes and returns raw bytes, so parsing cost is counted for classical and post-quantum alike.
- Garbage collection is off while timing; process priority is raised where permitted.
- Each algorithm is self-tested before timing (round trip must succeed, tampered input must fail).
- Sample counts are recorded per row (`min n` in Table A), because slow schemes get fewer samples.
