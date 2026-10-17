"""Build phase: recipe bundles, the build orchestration, verification, and the build manifest (build-v1).

Import boundaries: `_build` may import `_compiler`, `_runtime`, and `_channel`; nothing imports `_build` except `_cli`. The build is a consumer of `up`/`down`, never a reimplementation.
"""

from .orchestrate import (
    FALLBACK_BUILD_NAMESERVER,
    default_build_nameserver,
    DEFAULT_UPLINK_NETWORK,
    BuildError,
    BuildOptions,
    BuildResult,
    build_range,
    egress_build_spec,
    resolve_provisioning,
)
from .recipes import (
    DEFAULT_EXEC_BUDGET_MS,
    DEFAULT_RECIPE_BUDGET_S,
    RECIPES_DIR_NAME,
    RecipeError,
    RecipeInput,
    RecipeRun,
    RecipeSpec,
    RecipeTarget,
    ResolvedRecipe,
    default_recipe_cache,
    load_recipe,
    recipe_digest,
    resolve_recipe,
    run_recipe,
    validate_vars,
)

__all__ = [
    "FALLBACK_BUILD_NAMESERVER",
    "default_build_nameserver",
    "DEFAULT_EXEC_BUDGET_MS",
    "DEFAULT_RECIPE_BUDGET_S",
    "DEFAULT_UPLINK_NETWORK",
    "RECIPES_DIR_NAME",
    "BuildError",
    "BuildOptions",
    "BuildResult",
    "build_range",
    "egress_build_spec",
    "resolve_provisioning",
    "RecipeError",
    "RecipeInput",
    "RecipeRun",
    "RecipeSpec",
    "RecipeTarget",
    "ResolvedRecipe",
    "default_recipe_cache",
    "load_recipe",
    "recipe_digest",
    "resolve_recipe",
    "run_recipe",
    "validate_vars",
]
