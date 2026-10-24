
from pathlib import Path
import tempfile

cur_path = Path(r"G:\天体引擎\tianti\api\pipeline.py")
head_path = Path(tempfile.gettempdir()) / "pipeline_head.py"
cur = cur_path.read_text(encoding="utf-8").splitlines()
head = head_path.read_text(encoding="utf-8-sig").splitlines()
needle = '        "upstream": upstream,'
head_idx = head.index(needle)
suffix = head[head_idx + 1:]
print("cur lines:", len(cur), "head lines:", len(head), "append:", len(suffix))
cur_path.write_text("\n".join(cur + suffix) + "\n", encoding="utf-8")
print("recovered, new lines:", len(cur) + len(suffix))
