"""Profile configuration loader."""

from pathlib import Path
from typing import Any

import yaml

from core.models import Profile

DEFAULT_PROFILES_PATH = Path(__file__).parent / "profiles.yaml"


def load_profiles(config_path: Path | None = None) -> dict[str, dict[str, Any]]:
    """Load scan profiles from YAML configuration."""
    path = config_path or DEFAULT_PROFILES_PATH
    if not path.exists():
        raise FileNotFoundError(f"Profiles config not found: {path}")

    with path.open() as f:
        data = yaml.safe_load(f)

    return data.get("profiles", {})


def get_profile(profile: Profile, config_path: Path | None = None) -> dict[str, Any]:
    """Get specific profile configuration."""
    profiles = load_profiles(config_path)
    key = profile.value
    if key not in profiles:
        raise ValueError(f"Profile '{key}' not found in configuration")
    return profiles[key]


def get_global_config(config_path: Path | None = None) -> dict[str, Any]:
    """Get global configuration."""
    path = config_path or DEFAULT_PROFILES_PATH
    with path.open() as f:
        data = yaml.safe_load(f)
    return data.get("global", {})
