"""LLM client — abstraction layer for LLM providers.

Supports multiple LLM providers:
- OpenAI (GPT-4, GPT-3.5)
- Anthropic (Claude)

Provides unified interface for:
- Text generation
- JSON structured output
- Chat completions
"""

from __future__ import annotations

import json
from typing import Any, Literal

from src.utils.logger import get_logger

logger = get_logger(__name__)


class LLMClient:
    """Unified LLM client supporting multiple providers.

    Abstracts away provider-specific APIs to provide a consistent
    interface for text generation and structured output.
    """

    def __init__(
        self,
        provider: Literal["openai", "anthropic"] = "openai",
        model: str = "gpt-4o",
        api_key: str = "",
        base_url: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ) -> None:
        """Initialize the LLM client.

        Args:
            provider: LLM provider (openai or anthropic).
            model: Model name/identifier.
            api_key: API key for authentication.
            base_url: Custom API base URL (optional).
            temperature: Sampling temperature.
            max_tokens: Maximum tokens to generate.
        """
        self.provider = provider
        self.model = model
        self.api_key = api_key
        self.base_url = base_url
        self.temperature = temperature
        self.max_tokens = max_tokens

        self._client: Any = None

        logger.info("LLM client initialized", provider=provider, model=model)

    def _get_openai_client(self) -> Any:
        """Get or create OpenAI client."""
        if self._client is None:
            try:
                from langchain_openai import ChatOpenAI

                self._client = ChatOpenAI(
                    model=self.model,
                    api_key=self.api_key,
                    base_url=self.base_url,
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                )
            except ImportError:
                logger.error("langchain_openai not installed")
                raise
        return self._client

    def _get_anthropic_client(self) -> Any:
        """Get or create Anthropic client."""
        if self._client is None:
            try:
                from langchain_anthropic import ChatAnthropic

                self._client = ChatAnthropic(
                    model=self.model,
                    api_key=self.api_key,
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                )
            except ImportError:
                logger.error("langchain_anthropic not installed")
                raise
        return self._client

    def _get_client(self) -> Any:
        """Get the appropriate client based on provider."""
        if self.provider == "openai":
            return self._get_openai_client()
        elif self.provider == "anthropic":
            return self._get_anthropic_client()
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")

    async def generate(self, prompt: str, system_prompt: str | None = None) -> str:
        """Generate text from a prompt.

        Args:
            prompt: User prompt.
            system_prompt: Optional system prompt.

        Returns:
            Generated text.
        """
        try:
            from langchain_core.messages import HumanMessage, SystemMessage

            client = self._get_client()

            messages = []
            if system_prompt:
                messages.append(SystemMessage(content=system_prompt))
            messages.append(HumanMessage(content=prompt))

            response = await client.ainvoke(messages)
            return response.content

        except Exception as e:
            logger.error("LLM generation failed", error=str(e))
            raise

    async def generate_json(self, prompt: str, system_prompt: str | None = None) -> dict[str, Any]:
        """Generate structured JSON output.

        Args:
            prompt: User prompt requesting JSON.
            system_prompt: Optional system prompt.

        Returns:
            Parsed JSON dict.
        """
        # Add JSON instruction to prompt
        json_prompt = f"{prompt}\n\nRespond ONLY with valid JSON, no additional text."

        try:
            response_text = await self.generate(json_prompt, system_prompt)

            # Extract JSON from response
            json_text = self._extract_json(response_text)
            return json.loads(json_text)

        except json.JSONDecodeError as e:
            logger.error("Failed to parse LLM JSON response", error=str(e))
            raise
        except Exception as e:
            logger.error("LLM JSON generation failed", error=str(e))
            raise

    async def chat(
        self,
        messages: list[dict[str, str]],
        temperature: float | None = None,
    ) -> str:
        """Chat completion with message history.

        Args:
            messages: List of message dicts with 'role' and 'content'.
            temperature: Override temperature for this request.

        Returns:
            Assistant response text.
        """
        try:
            from langchain_core.messages import (
                AIMessage,
                HumanMessage,
                SystemMessage,
            )

            client = self._get_client()

            # Convert to LangChain messages
            lc_messages = []
            for msg in messages:
                role = msg.get("role", "user")
                content = msg.get("content", "")

                if role == "system":
                    lc_messages.append(SystemMessage(content=content))
                elif role == "assistant":
                    lc_messages.append(AIMessage(content=content))
                else:
                    lc_messages.append(HumanMessage(content=content))

            response = await client.ainvoke(lc_messages)
            return response.content

        except Exception as e:
            logger.error("LLM chat failed", error=str(e))
            raise

    def _extract_json(self, text: str) -> str:
        """Extract JSON from LLM response text.

        Handles cases where LLM wraps JSON in markdown code blocks.

        Args:
            text: Raw LLM response text.

        Returns:
            Extracted JSON string.
        """
        # Try to find JSON in code blocks
        if "```json" in text:
            start = text.find("```json") + 7
            end = text.find("```", start)
            if end > start:
                return text[start:end].strip()

        if "```" in text:
            start = text.find("```") + 3
            end = text.find("```", start)
            if end > start:
                return text[start:end].strip()

        # Try to find JSON object directly
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            return text[start:end]

        # Return as-is and let json.loads handle errors
        return text.strip()

    async def close(self) -> None:
        """Close the LLM client."""
        self._client = None