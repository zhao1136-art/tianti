"""危险行为检测与风险判定（实现见 detect 包子模块）。"""

from .base import SEVERITIES, DetectorHit, DetectorSpec

__all__ = ["SEVERITIES", "DetectorHit", "DetectorSpec"]
