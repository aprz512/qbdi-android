from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class OffsetScene:
    name: str
    start_offset: int
    end_offset: int


@dataclass(frozen=True)
class SymbolScene:
    name: str
    symbol: str


SceneSpec = OffsetScene | SymbolScene


@dataclass(frozen=True)
class AppConfig:
    package: str
    apk: Path | None


@dataclass(frozen=True)
class TargetConfig:
    module: str
    binary: Path | None


@dataclass(frozen=True)
class TracerConfig:
    profile: str
    compression: bool
    flight_enabled: bool
    flight_entry_scene: str | None
    library: Path | None
    companion: Path | None


@dataclass(frozen=True)
class UserConfig:
    schema_version: int
    app: AppConfig
    target: TargetConfig
    tracer: TracerConfig
    scenes: tuple[SceneSpec, ...]


@dataclass(frozen=True)
class ElfIdentity:
    elf_class: str
    machine: str
    build_id: str
    executable_ranges: tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class ResolvedScene:
    name: str
    start_offset: int
    end_offset: int


@dataclass(frozen=True)
class ResolvedTarget:
    package: str
    module: str
    host_binary: Path
    device_binary: str
    identity: ElfIdentity
    scenes: tuple[ResolvedScene, ...]
