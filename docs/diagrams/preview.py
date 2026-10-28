"""Regenerate all diagrams and render them to SVG without a full docs build.

The Quarto docs build converts `.excalidraw` images automatically via the inspect-docs excalidraw filter; this script is for everything else: previewing diagrams during development, and producing the SVGs referenced by documents outside the docs project (e.g. `design/ranges-overview.qmd`).

Run from any directory:

    python3 docs/diagrams/preview.py

Requires Node.js. The converter's npm dependencies are installed on first use.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import containment
import cyris_basic
import defender_ops
import dmz_pivot
import equifax
import goad_light
import image_layers
import kypo_demo
import range_host
import splunk_detection
import vulhub_zabbix

DIAGRAMS = [
    dmz_pivot,
    containment,
    image_layers,
    range_host,
    vulhub_zabbix,
    kypo_demo,
    cyris_basic,
    equifax,
    goad_light,
    splunk_detection,
    defender_ops,
]

# Example topology SVGs are copied beside each example's README (the real file
# must live there for GitHub to render it) AND into docs/examples/ beside the
# symlinked pages (a real copy, not a symlink: Quarto reproduces a symlinked
# resource as a symlink in _site, which dangles and fails the next render).
EXAMPLE_TOPOLOGIES = {
    "dmz-pivot": "_dmz_pivot",
    "vulhub-zabbix": "_vulhub_zabbix",
    "kypo-demo": "_kypo_demo",
    "cyris-basic": "_cyris_basic",
    "equifax": "_equifax",
    "goad-light": "_goad_light",
    "splunk-detection": "_splunk_detection",
    "defender-ops": "_defender_ops",
}


def main() -> None:
    """Regenerate every `.excalidraw` file and render each to `<name>.excalidraw.svg`."""
    diagrams_dir = Path(__file__).parent
    excalidraw_dir = (
        diagrams_dir.parent
        / "_extensions/meridianlabs-ai/inspect-docs/resources/excalidraw"
    )
    converter = excalidraw_dir / "excalidraw-to-svg.mjs"

    for module in DIAGRAMS:
        module.main()

    if not (excalidraw_dir / "node_modules").is_dir():
        print("installing converter dependencies (first use) ...")
        subprocess.run(
            ["npm", "install", "--no-audit", "--no-fund"],
            cwd=excalidraw_dir,
            check=True,
            stdout=subprocess.DEVNULL,
        )

    for src in sorted(diagrams_dir.glob("*.excalidraw")):
        svg = diagrams_dir / f"{src.name}.svg"
        subprocess.run(
            ["node", str(converter), str(src), str(svg), "--theme", "light"],
            check=True,
            capture_output=True,
        )
        print(f"  wrote {svg}")
        # The committed raster the design docs reference (SVG does not survive
        # the docx render); 2x for print resolution, clamped to the text
        # column by the renderer.
        png = diagrams_dir / f"{src.name}.png"
        subprocess.run(
            ["rsvg-convert", "-z", "2", str(svg), "-o", str(png)],
            check=True,
        )
        print(f"  wrote {png}")

    examples_dir = diagrams_dir.parent.parent / "src/inspect_ranges/examples"
    pages_dir = diagrams_dir.parent / "examples"
    for name, example in EXAMPLE_TOPOLOGIES.items():
        svg = diagrams_dir / f"{name}.excalidraw.svg"
        for topology in (
            examples_dir / example / f"{name}-topology.svg",
            pages_dir / f"{name}-topology.svg",
        ):
            shutil.copyfile(svg, topology)
            print(f"  wrote {topology}")


if __name__ == "__main__":
    main()
