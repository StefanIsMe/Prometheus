"""prometheus application settings — pydantic-settings powered."""

from __future__ import annotations

from typing import Literal

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


ReasoningEffort = Literal["none", "minimal", "low", "medium", "high", "xhigh"]

_BASE_CONFIG = SettingsConfigDict(
    case_sensitive=False,
    populate_by_name=True,
    extra="ignore",
)


class LlmSettings(BaseSettings):
    model_config = _BASE_CONFIG

    # Model routing comes from ~/.prometheus/llm.yaml and env vars.
    model: str | None = Field(default=None, alias="prometheus_LLM")
    api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("LLM_API_KEY", "OPENAI_API_KEY"),
    )
    api_base: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "LLM_API_BASE",
            "OPENAI_API_BASE",
            "OPENAI_BASE_URL",
            "LITELLM_BASE_URL",
            "OLLAMA_API_BASE",
        ),
    )
    reasoning_effort: ReasoningEffort = Field(default="xhigh", alias="prometheus_REASONING_EFFORT")
    timeout: int = Field(default=300, alias="LLM_TIMEOUT")


class RuntimeSettings(BaseSettings):
    model_config = _BASE_CONFIG

    image: str = Field(
        default="prometheus-sandbox:local",
        alias="prometheus_IMAGE",
    )
    backend: str = Field(default="docker", alias="prometheus_RUNTIME_BACKEND")
    max_concurrent_scans: int = Field(default=2, alias="prometheus_MAX_CONCURRENT_SCANS")
    runs_dir: str | None = Field(default=None, alias="prometheus_RUNS_DIR")


class Settings(BaseSettings):
    model_config = _BASE_CONFIG

    llm: LlmSettings = Field(default_factory=LlmSettings)
    runtime: RuntimeSettings = Field(default_factory=RuntimeSettings)
