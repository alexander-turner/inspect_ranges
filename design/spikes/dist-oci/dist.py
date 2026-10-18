"""Drive the slice-1 distribution surfaces for the dist-oci battery (the CLI verbs arrive with Q8 in slice 3)."""

import argparse
import sys
from pathlib import Path

from inspect_ranges._build.manifest import load_manifest
from inspect_ranges._dist import DistError, OciLayout, materialize_closure, push_build


def cmd_push(args: argparse.Namespace) -> int:
    manifest = load_manifest(Path(args.build_cache), args.range_name)
    if manifest is None:
        print(f"no manifest for {args.range_name} in {args.build_cache}", file=sys.stderr)
        return 1
    layout = OciLayout(Path(args.layout)).ensure()
    root = push_build(
        manifest,
        layout,
        image_cache=Path(args.image_cache),
        build_cache=Path(args.build_cache),
        range_dir=Path(args.range_dir),
    )
    print(f"root {root.digest}")
    return 0


def cmd_pull(args: argparse.Namespace) -> int:
    layout = OciLayout(Path(args.layout)).open()
    root = layout.ref(args.ref)
    result = materialize_closure(
        layout,
        root,
        image_cache=Path(args.image_cache),
        build_cache=Path(args.build_cache),
        recipe_cache=Path(args.recipe_cache),
    )
    print(f"fetched {len(result.fetched)}: {' '.join(sorted(result.fetched))}")
    print(f"present {len(result.present)}")
    if result.superseded_built_at:
        print(f"superseded {result.superseded_built_at}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    push = sub.add_parser("push")
    push.add_argument("--range-name", required=True)
    push.add_argument("--build-cache", required=True)
    push.add_argument("--image-cache", required=True)
    push.add_argument("--range-dir", required=True)
    push.add_argument("--layout", required=True)
    push.set_defaults(fn=cmd_push)
    pull = sub.add_parser("pull")
    pull.add_argument("--layout", required=True)
    pull.add_argument("--ref", required=True)
    pull.add_argument("--image-cache", required=True)
    pull.add_argument("--build-cache", required=True)
    pull.add_argument("--recipe-cache", required=True)
    pull.set_defaults(fn=cmd_pull)
    args = parser.parse_args()
    try:
        return int(args.fn(args))
    except DistError as error:
        print(f"refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
