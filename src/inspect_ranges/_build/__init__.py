"""Build phase: recipe bundles, the build orchestration, verification, and the build manifest (build-v1).

Import boundaries: `_build` may import `_compiler`, `_runtime`, and `_channel`; nothing imports `_build` except `_cli`. The build is a consumer of `up`/`down`, never a reimplementation.
"""

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
    "DEFAULT_EXEC_BUDGET_MS",
    "DEFAULT_RECIPE_BUDGET_S",
    "RECIPES_DIR_NAME",
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
