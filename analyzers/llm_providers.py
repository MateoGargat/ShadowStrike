"""Unified multi-provider LLM abstraction using instructor for structured output."""

from __future__ import annotations

import logging
from typing import Optional

import instructor
from pydantic import BaseModel

from core.models import AppConfig

logger = logging.getLogger(__name__)


class LLMProvider:
    """Unified interface for calling different LLM providers via instructor."""

    def __init__(self, config: AppConfig):
        self.config = config
        self._clients: dict[str, instructor.Instructor] = {}

    def call(
        self,
        provider: str,
        model: str,
        system_prompt: str,
        user_prompt: str,
        response_model: type[BaseModel],
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ) -> BaseModel:
        """Make a unified call to any supported provider.

        Args:
            provider: One of "groq", "openai", "anthropic".
            model: Model identifier for the provider.
            system_prompt: System message content.
            user_prompt: User message content.
            response_model: Pydantic model for structured output.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.

        Returns:
            An instance of response_model with the LLM's structured output.

        Raises:
            ValueError: If provider is unsupported or unavailable.
            Exception: If the LLM call fails.
        """
        client = self._get_client(provider)

        if provider == "anthropic":
            return client.messages.create(
                model=model,
                response_model=response_model,
                messages=[
                    {"role": "user", "content": f"{system_prompt}\n\n{user_prompt}"},
                ],
                temperature=temperature,
                max_tokens=max_tokens,
            )

        return client.chat.completions.create(
            model=model,
            response_model=response_model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=temperature,
            max_tokens=max_tokens,
            max_retries=2,
        )

    def _get_client(self, provider: str) -> instructor.Instructor:
        """Get or lazily initialize an instructor client for the given provider."""
        if provider in self._clients:
            return self._clients[provider]

        if provider == "groq":
            client = self._init_groq_client()
        elif provider == "openai":
            client = self._init_openai_client()
        elif provider == "anthropic":
            client = self._init_anthropic_client()
        else:
            raise ValueError(f"Unsupported LLM provider: {provider}")

        self._clients[provider] = client
        return client

    def _init_groq_client(self) -> instructor.Instructor:
        if not self.config.groq_api_key:
            raise ValueError("Groq API key not configured")
        from groq import Groq
        return instructor.from_groq(
            Groq(api_key=self.config.groq_api_key),
            mode=instructor.Mode.JSON,
        )

    def _init_openai_client(self) -> instructor.Instructor:
        if not self.config.openai_api_key:
            raise ValueError("OpenAI API key not configured")
        from openai import OpenAI
        return instructor.from_openai(
            OpenAI(api_key=self.config.openai_api_key),
            mode=instructor.Mode.JSON,
        )

    def _init_anthropic_client(self) -> instructor.Instructor:
        if not self.config.anthropic_api_key:
            raise ValueError("Anthropic API key not configured")
        from anthropic import Anthropic
        return instructor.from_anthropic(
            Anthropic(api_key=self.config.anthropic_api_key),
            mode=instructor.Mode.JSON,
        )

    def get_available_providers(self) -> list[str]:
        """Return the list of providers that have an API key configured."""
        available = []
        if self.config.groq_api_key:
            available.append("groq")
        if self.config.openai_api_key:
            available.append("openai")
        if self.config.anthropic_api_key:
            available.append("anthropic")
        return available
