"""Build phase: recipe bundles, the build orchestration, verification, and the build manifest (build-v1).

Import boundaries: `_build` may import `_compiler`, `_runtime`, and `_channel`; nothing imports `_build` except `_cli`. The build is a consumer of `up`/`down`, never a reimplementation.
"""

from .orchestrate import (
    DEFAULT_UPLINK_NETWORK,
    FALLBACK_BUILD_NAMESERVER,
    BuildError,
    BuildOptions,
    BuildResult,
    ResolvedStep,
    build_range,
    default_build_nameserver,
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
    StageSink,
    default_recipe_cache,
    load_recipe,
    recipe_digest,
    resolve_recipe,
    run_recipe,
    validate_vars,
)

__all__ = [
    "DEFAULT_EXEC_BUDGET_MS",
    "DEFAULT_RECIPE_BUDGET_S",
    "DEFAULT_UPLINK_NETWORK",
    "FALLBACK_BUILD_NAMESERVER",
    "RECIPES_DIR_NAME",
    "BuildError",
    "BuildOptions",
    "BuildResult",
    "RecipeError",
    "RecipeInput",
    "RecipeRun",
    "RecipeSpec",
    "RecipeTarget",
    "ResolvedRecipe",
    "ResolvedStep",
    "StageSink",
    "build_range",
    "default_build_nameserver",
    "default_recipe_cache",
    "egress_build_spec",
    "load_recipe",
    "recipe_digest",
    "resolve_provisioning",
    "resolve_recipe",
    "run_recipe",
    "validate_vars",
]
