
import time, json, shutil, tempfile, os
from tianti.api import pipeline
from tianti.core.config import Config

cfg = Config.load()
shutil.rmtree(cfg.paths.work / "trace_cache", ignore_errors=True)  # 清缓存，测首次

t0 = time.perf_counter()
r1 = pipeline.scan_path("samples/sim/hello.ps1", config=cfg)
t1 = time.perf_counter()
t2 = time.perf_counter()
r2 = pipeline.scan_path("samples/sim/hello.ps1", config=cfg)
t3 = time.perf_counter()
r3 = pipeline.scan_path("samples/sim/hello.ps1", config=cfg, static_only=True)
t4 = time.perf_counter()

extra1 = (r1.trace.get("extra") or {}) if isinstance(r1.trace, dict) else {}
print("first  %.2fs backend=%s" % (t1 - t0, (r1.extra.get("backend") or {}).get("backend")))
print("timings:", json.dumps(extra1.get("timings"), ensure_ascii=False))
print("second %.2fs backend=%s note=%s" % (t3 - t2, (r2.extra.get("backend") or {}).get("backend"), (r2.notes or [''])[0][:40]))
print("static %.2fs input=%s" % (t4 - t3, r3.extra.get("input")))
