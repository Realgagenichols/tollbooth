"""Plugin loading: config-declared interceptors (R13).

Plugins are explicit `module:factory` import specs from tollbooth.yaml —
never auto-discovered entry points: installing a package must not silently
insert an interceptor into the pipeline. Every load failure aborts startup
(fail-fast) naming the plugin; messages carry exception TYPES only, since
arbitrary exception text may echo settings values (Pattern 11).
"""

from dataclasses import dataclass
from importlib import import_module

from tollbooth.config import ConfigError, PluginConfig
from tollbooth.pipeline import RequestInterceptor, ResultInterceptor

# Built-in interceptor names: a plugin shadowing one would make audit
# reason_ids (e.g. "interceptor-failure:policy") ambiguous.
RESERVED_NAMES = frozenset({"policy", "dlp-request", "dlp-result"})


@dataclass(frozen=True)
class PluginSet:
    """Loaded plugin interceptors per pipeline path, in declared order."""

    request: tuple[RequestInterceptor, ...] = ()
    result: tuple[ResultInterceptor, ...] = ()


def _instantiate(spec: PluginConfig) -> object:
    module_name, _, factory_name = spec.plugin.partition(":")
    try:
        module = import_module(module_name)
    except Exception as exc:
        raise ConfigError(
            f"plugin {spec.plugin!r}: import failed ({type(exc).__name__})"
        ) from exc
    factory = getattr(module, factory_name, None)
    if not callable(factory):
        raise ConfigError(f"plugin {spec.plugin!r}: {factory_name!r} is not a callable factory")
    try:
        return factory(dict(spec.settings))
    except Exception as exc:
        raise ConfigError(
            f"plugin {spec.plugin!r}: factory raised {type(exc).__name__}"
        ) from exc


def load_plugins(specs: list[PluginConfig]) -> PluginSet:
    """Instantiate all declared plugins or raise ConfigError on the first bad one."""
    request: list[RequestInterceptor] = []
    result: list[ResultInterceptor] = []
    taken: set[str] = set(RESERVED_NAMES)
    for spec in specs:
        interceptor = _instantiate(spec)
        name = getattr(interceptor, "name", None)
        if not isinstance(name, str) or not name:
            raise ConfigError(f"plugin {spec.plugin!r}: interceptor has no usable 'name'")
        if name in taken:
            raise ConfigError(
                f"plugin {spec.plugin!r}: interceptor name {name!r} collides with "
                "a built-in or another plugin"
            )
        taken.add(name)
        handles_request = callable(getattr(interceptor, "check_request", None))
        handles_result = callable(getattr(interceptor, "check_result", None))
        if not handles_request and not handles_result:
            raise ConfigError(
                f"plugin {spec.plugin!r}: interceptor {name!r} implements "
                "neither check_request nor check_result"
            )
        if handles_request:
            request.append(interceptor)
        if handles_result:
            result.append(interceptor)
    return PluginSet(request=tuple(request), result=tuple(result))
