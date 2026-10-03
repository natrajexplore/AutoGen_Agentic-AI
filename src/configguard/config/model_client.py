"""Model client factory: switch providers by changing MODEL_PROVIDER / MODEL in .env.

API keys are read by each client from its standard environment variable
(OPENAI_API_KEY, ANTHROPIC_API_KEY); they are never passed through ConfigGuard code.
"""

from __future__ import annotations

from autogen_core.models import ChatCompletionClient

from configguard.config.settings import Settings


def build_model_client(settings: Settings) -> ChatCompletionClient:
    if settings.model_provider == "openai":
        from autogen_ext.models.openai import OpenAIChatCompletionClient

        return OpenAIChatCompletionClient(model=settings.model, temperature=0)
    if settings.model_provider == "anthropic":
        # requires: uv add "autogen-ext[anthropic]==0.7.5"
        from autogen_ext.models.anthropic import AnthropicChatCompletionClient

        return AnthropicChatCompletionClient(model=settings.model, temperature=0)
    if settings.model_provider == "ollama":
        # requires: uv add "autogen-ext[ollama]==0.7.5"; the model must support tool calling
        from autogen_ext.models.ollama import OllamaChatCompletionClient

        return OllamaChatCompletionClient(model=settings.model, host=settings.ollama_host, options={"temperature": 0})
    raise ValueError(f"unsupported MODEL_PROVIDER {settings.model_provider!r} (use openai, anthropic or ollama)")
