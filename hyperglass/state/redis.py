"""Interact with redis for state management."""

# Standard Library
import json
import base64
import typing as t
from types import TracebackType
from typing import overload
from datetime import datetime, timedelta

# Project
from hyperglass.log import log
from hyperglass.exceptions.private import StateError

if t.TYPE_CHECKING:
    # Third Party
    from redis import Redis
    from redis.client import Pipeline


class StateDecodeError(StateError):
    """Raised when a cached value cannot be decoded.

    Most commonly seen when upgrading hyperglass: values previously written
    with the legacy `pickle` codec are unreadable by the JSON codec. The query
    cache self-expires, and configuration is rewritten on startup, so the
    correct response is to treat the key as a cache miss.
    """


def _encode(value: t.Any) -> bytes:
    """Serialize a value for storage in Redis as JSON.

    `bytes` are base64-encoded (there is no bytes literal in JSON). Pydantic
    models are coerced to JSON-native dicts via `model_dump(mode="json")` so
    non-JSON-native field types (Url, Path, IPvAnyAddress, etc.) are stringified
    automatically; callers revalidate back to models at the typed-accessor layer
    (see `HyperglassState`). Plain JSON-native values pass straight through.
    """
    if isinstance(value, bytes):
        return json.dumps({"__bytes__": base64.b64encode(value).decode()}).encode()
    if hasattr(value, "model_dump_json"):
        return value.model_dump_json().encode()
    return json.dumps(value).encode()


def _decode(raw: bytes) -> t.Any:
    """Deserialize a value previously written by `_encode`.

    Raises `StateDecodeError` for non-JSON payloads (e.g. legacy pickled
    values from older hyperglass releases) instead of crashing, so callers can
    treat the failure as a cache miss.
    """
    try:
        decoded = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as err:
        raise StateDecodeError("Cached value is not valid JSON: {err}", err=err) from err
    if isinstance(decoded, t.Dict) and set(decoded.keys()) == {"__bytes__"}:
        return base64.b64decode(decoded["__bytes__"])
    return decoded


class RedisManager:
    """Convenience wrapper for managing a redis session."""

    instance: "Redis"
    namespace: str

    def __init__(self, instance: "Redis", namespace: str) -> None:
        """Set up Redis connection and add configuration objects."""
        self.instance = instance
        self.namespace = namespace

    def __repr__(self) -> str:
        """Alias repr to Redis instance's repr."""
        return repr(self.instance)

    def __str__(self) -> str:
        """String-friendly redis manager."""
        return repr(self)

    def _key_join(self, *keys: str) -> str:
        """Format keys with state namespace."""
        key_in_parts = (k for key in keys for k in key.split("."))
        key_parts = list(dict.fromkeys((*self.namespace.split("."), *key_in_parts)))
        return ".".join(key_parts)

    def key(self, key: t.Union[str, t.Sequence[str]]) -> str:
        """Format keys with state namespace."""
        if isinstance(key, (t.List, t.Tuple, t.Generator)):
            return self._key_join(*key)
        return self._key_join(key)

    def check(self) -> bool:
        """Ensure the redis instance is running and reachable."""
        result = self.instance.ping()
        if result is False:
            raise RuntimeError(
                "Redis instance {!r} is not running or reachable".format(self.instance)
            )
        return result

    def delete(self, key: t.Union[str, t.Sequence[str]]) -> None:
        """Delete a key and value from the cache."""
        self.instance.delete(self.key(key))

    def expire(
        self,
        key: t.Union[str, t.Sequence[str]],
        *,
        expire_in: t.Optional[t.Union[timedelta, int]] = None,
        expire_at: t.Optional[t.Union[datetime, int]] = None,
    ) -> None:
        """Expire a cache key, either at a time, or in a number of seconds.

        If no at or in time is specified, the key is deleted.
        """
        key = self.key(key)
        if isinstance(expire_at, (datetime, int)):
            self.instance.expireat(key, expire_at)
            return
        if isinstance(expire_in, (timedelta, int)):
            self.instance.expire(key, expire_in)
            return
        self.instance.delete(key)

    def get(
        self,
        key: t.Union[str, t.Sequence[str]],
        *,
        raise_if_none: bool = False,
        value_if_none: t.Any = None,
    ) -> t.Union[None, t.Any]:
        """Get and decode a value from the cache."""
        name = self.key(key)
        value: t.Optional[bytes] = self.instance.get(name)
        if isinstance(value, bytes):
            try:
                return _decode(value)
            except StateDecodeError as err:
                log.bind(key=key, name=name).warning(
                    "Ignoring undecodable cached value (treating as cache miss): {err}", err=err
                )
                self.instance.delete(name)
                value = None
        if raise_if_none is True:
            raise StateError("'{key}' ('{name}') does not exist in Redis store", key=key, name=name)
        if value_if_none is not None:
            return value_if_none
        return None

    def set(self, key: t.Union[str, t.Sequence[str]], value: t.Any) -> None:
        """Add an object to the cache."""
        name = self.key(key)
        self.instance.set(name, _encode(value))

    @overload
    def get_map(self, key: str, item: str) -> t.Any:
        """Get a single value from a Redis hash map (dict)."""

    @overload
    def get_map(self, key: str, item=None) -> t.Any:
        """Get a single value from a Redis hash map (dict)."""

    def get_map(self, key: str, item: t.Optional[str] = None) -> t.Any:
        """Get a Redis hash map or hash map value."""
        name = self.key(key)
        if isinstance(item, str):
            raw = self.instance.hget(name, item)
            if raw is None:
                return None
            values = {item: raw}
        else:
            values = self.instance.hgetall(name)

        decoded: t.Dict[str, t.Any] = {}
        for field, raw in values.items():
            # Redis hash field names come back as bytes; normalize to str.
            field_name = field.decode() if isinstance(field, bytes) else field
            if not isinstance(raw, bytes):
                continue
            try:
                decoded[field_name] = _decode(raw)
            except StateDecodeError as err:
                log.bind(key=key, field=field_name).warning(
                    "Ignoring undecodable cached map item: {err}", err=err
                )
                self.instance.hdel(name, field_name)

        if isinstance(item, str):
            return decoded.get(item)
        return decoded

    def set_map_item(self, key: str, item: str, value: t.Any) -> None:
        """Add a value to a hash map (dict)."""
        name = self.key(key)
        self.instance.hset(name, item, _encode(value))

    def pipeline(self):
        """Enter a Redis Pipeline, but expose all the custom interaction methods."""
        # Copy the base RedisManager and remove the pipeline method (this method).
        ctx = type(
            "RedisManagerExcludePipeline",
            (RedisManager,),
            {k: v for k, v in self.__dict__.items() if k != "pipeline"},
        )

        def nested_pipeline(*_, **__) -> None:
            """Ensure pipeline is never called from within pipeline."""
            raise AttributeError("Cannot access pipeline from pipeline")

        class RedisManagerPipeline(ctx):
            """Copy of RedisManager, but uses `Redis.pipeline` as the `instance`."""

            parent: "Redis"
            instance: "Pipeline"
            pipeline: t.Any = nested_pipeline

            def __init__(
                pipeline_self,  # noqa: N805 Avoid `self` namespace conflict
                *,
                parent: "Redis",
                instance: "Pipeline",
                namespace: str,
            ) -> None:
                pipeline_self.parent = parent
                super().__init__(instance=instance, namespace=namespace)

            def __enter__(
                pipeline_self: "RedisManagerPipeline",  # noqa: N805 Avoid `self` namespace conflict
            ) -> "RedisManagerPipeline":
                return pipeline_self

            def __exit__(
                pipeline_self: "RedisManagerPipeline",  # noqa: N805 Avoid `self` namespace conflict
                exc_type: t.Optional[t.Type[BaseException]] = None,
                exc_value: t.Optional[BaseException] = None,
                _: t.Optional[TracebackType] = None,
            ) -> None:
                pipeline_self.instance.execute()
                if exc_type is not None:
                    log.bind(
                        pipeline=repr(pipeline_self),
                        parent=repr(pipeline_self.parent),
                        error=exc_value,
                    ).error(
                        "Error exiting pipeline",
                    )

        return RedisManagerPipeline(
            parent=self.instance,
            instance=self.instance.pipeline(),
            namespace=self.namespace,
        )
