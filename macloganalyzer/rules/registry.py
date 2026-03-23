from __future__ import annotations
import importlib
import pkgutil
import logging
from pathlib import Path

from macloganalyzer.rules.base import BaseRule

logger = logging.getLogger(__name__)


def discover_rules() -> list[BaseRule]:
    """Auto-discover all BaseRule subclasses in rules subpackages."""
    rules_pkg_path = Path(__file__).parent
    rules: list[BaseRule] = []

    for pkg_dir in sorted(rules_pkg_path.iterdir()):
        if not pkg_dir.is_dir() or pkg_dir.name.startswith("_"):
            continue
        pkg_name = f"macloganalyzer.rules.{pkg_dir.name}"
        try:
            importlib.import_module(pkg_name)
        except ImportError:
            continue

        for _, mod_name, _ in pkgutil.iter_modules([str(pkg_dir)]):
            full_name = f"{pkg_name}.{mod_name}"
            try:
                mod = importlib.import_module(full_name)
                for attr_name in dir(mod):
                    obj = getattr(mod, attr_name)
                    if (
                        isinstance(obj, type)
                        and issubclass(obj, BaseRule)
                        and obj is not BaseRule
                        and getattr(obj, "id", "")
                    ):
                        rules.append(obj())
                        logger.debug(f"Loaded rule {obj.id} from {full_name}")
            except Exception as e:
                logger.warning(f"Failed to load rule module {full_name}: {e}")

    return rules
