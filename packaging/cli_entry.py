"""PyInstaller CLI 入口：tianti。"""

from __future__ import annotations

import sys

from tianti.cli import main

if __name__ == "__main__":
    sys.exit(main())
