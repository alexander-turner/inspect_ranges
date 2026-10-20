"""Drive push/pull/copy across store forms for the dist-registry battery (CLI verbs arrive with Q8 in slice 3).

Store URIs: `layout:/abs/path` or `registry+http://host:port/repo/path`.
"""

import argparse
import sys
from pathlib import Path
from urllib.parse import urlparse

from inspect_ranges._build.manifest import load_manifest
from inspect_ranges._dist import (
    ContentStore,
    DistError,
    OciLayout,
    RegistryRepo,
    copy_closure,
    materialize_closure,
    push_build,
)


def store_for(uri: str, *, create: bool = False) -> ContentStore:
    if uri.startswith("layout:"):
        layout = OciLayout(Path(uri.removeprefix("layout:")))
        return layout.ensure() if create else layout.open()
    if uri.startswith("registry+"):
        parsed = urlparse(uri.removeprefix("registry+"))
        return RegistryRepo(
            f"{parsed.scheme}://{parsed.netloc}", parsed.path.strip("/")
        )
    raise SystemExit(f"unknown store uri {uri!r}")


def cmd_push(args: argparse.Namespace) -> int:
    manifest = load_manifest(Path(args.build_cache), args.range_name)
    if manifest is None:
        print(f"no manifest for {args.range_name}", file=sys.stderr)
        return 1
    store = store_for(args.store, create=True)
    root = push_build(
        manifest,
        store,
        image_cache=Path(args.image_cache),
        build_cache=Path(args.build_cache),
        range_dir=Path(args.range_dir),
    )
    print(f"root {root.digest}")
    return 0


def cmd_pull(args: argparse.Namespace) -> int:
    store = store_for(args.store)
    result = materialize_closure(
        store,
        store.ref(args.ref),
        image_cache=Path(args.image_cache),
        build_cache=Path(args.build_cache),
        recipe_cache=Path(args.recipe_cache),
    )
    print(f"fetched {len(result.fetched)}: {' '.join(sorted(result.fetched))}")
    print(f"present {len(result.present)}")
    return 0


def cmd_copy(args: argparse.Namespace) -> int:
    source = store_for(args.source)
    destination = store_for(args.dest, create=True)
    result = copy_closure(source, destination, source.ref(args.ref), name=args.ref)
    print(f"copied {len(result.copied)} present {len(result.present)} root {result.root}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    push = sub.add_parser("push")
    for flag in ("--range-name", "--build-cache", "--image-cache", "--range-dir", "--store"):
        push.add_argument(flag, required=True)
    push.set_defaults(fn=cmd_push)
    pull = sub.add_parser("pull")
    for flag in ("--store", "--ref", "--image-cache", "--build-cache", "--recipe-cache"):
        pull.add_argument(flag, required=True)
    pull.set_defaults(fn=cmd_pull)
    copy = sub.add_parser("copy")
    for flag in ("--source", "--dest", "--ref"):
        copy.add_argument(flag, required=True)
    copy.set_defaults(fn=cmd_copy)
    args = parser.parse_args()
    try:
        return int(args.fn(args))
    except DistError as error:
        print(f"refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
