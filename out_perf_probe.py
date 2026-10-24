
import time, os, tempfile
from pathlib import Path
from tianti.sandbox import isolation, snapshot, containment
from tianti.core.model import Sample
from tianti.core.config import Config
from tianti.sandbox.base import SandboxPolicy

def t(label, fn):
    start = time.perf_counter()
    out = fn()
    print(f"{label}: {time.perf_counter()-start:.2f}s")
    return out

iso = isolation.Isolation(trace_id="perfprobe", network="blocked", use_firewall=True)
try:
    t("iso.prepare(firewall)", lambda: iso.prepare(r"C:\Windows\System32\cmd.exe"))
    print("isolation items:", iso.items)
finally:
    t("iso.cleanup", iso.cleanup)

tmp = Path(tempfile.mkdtemp(prefix="probe_iso_"))
try:
    (tmp / "a.txt").write_text("hello")
    t("icacls dir+file", lambda: containment._set_tree_low_integrity(tmp))
    t("icacls file again", lambda: containment._set_tree_low_integrity(tmp / "a.txt", recursive=False))
finally:
    import shutil; shutil.rmtree(tmp, ignore_errors=True)

t("snapshot_tree(empty)", lambda: snapshot.snapshot_tree(tempfile.mkdtemp(prefix="probe_snap_")))
t("export_registry(5 subtrees)", lambda: snapshot.export_registry(snapshot.DEFAULT_REG_SUBTREES))

# 全流程：hello.ps1
cfg = Config.load()
policy = SandboxPolicy.from_config(cfg.policy("deep"))
from tianti.sandbox.containment import ContainmentBackend
backend = ContainmentBackend()
start = time.perf_counter()
trace = backend.run(Sample.from_path("samples/sim/hello.ps1"), policy)
total = time.perf_counter() - start
print(f"FULL hello.ps1: {total:.2f}s events={len(trace.events)}")
print("extra keys:", sorted(trace.extra.keys()))
print("isolation:", trace.sandbox.isolation)
