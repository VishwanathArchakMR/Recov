import os
import json
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Type, Optional
from pydantic import BaseModel
from config import settings

logger = logging.getLogger(__name__)


class BaseLLMProvider(ABC):
    """Abstract LLM Provider interface."""

    @abstractmethod
    def generate_structured_response(
        self, prompt: str, schema: Type[BaseModel], system_instruction: str = ""
    ) -> Optional[BaseModel]:
        """Generate structured response matching a Pydantic schema."""
        pass

    @abstractmethod
    def generate_text(
        self, prompt: str, system_instruction: str = ""
    ) -> Optional[str]:
        """Generate unstructured text response."""
        pass


class GeminiLLMProvider(BaseLLMProvider):
    """Official Google GenAI SDK Provider implementation for Gemini 3.1 Flash-Lite."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY") or getattr(settings, "GEMINI_API_KEY", None)
        self.model = model or os.getenv("GEMINI_MODEL") or getattr(settings, "GEMINI_MODEL", "gemini-3.1-flash-lite")
        self._client = None

    def _get_client(self):
        # Always re-check env variable if key wasn't set at init
        if not self.api_key:
            self.api_key = os.getenv("GEMINI_API_KEY") or getattr(settings, "GEMINI_API_KEY", None)
        if not self.api_key:
            return None
        if self._client is None:
            try:
                from google import genai
                self._client = genai.Client(api_key=self.api_key)
            except Exception as e:
                logger.warning(f"Failed to initialize Google GenAI client: {e}")
                return None
        return self._client

    def generate_structured_response(
        self, prompt: str, schema: Type[BaseModel], system_instruction: str = ""
    ) -> Optional[BaseModel]:
        client = self._get_client()
        if not client:
            return None
        try:
            from google.genai import types
            config = types.GenerateContentConfig(
                system_instruction=system_instruction if system_instruction else None,
                response_mime_type="application/json",
                response_schema=schema,
                temperature=0.1,
            )
            response = client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=config,
            )
            if not response or not response.text:
                return None
            parsed_json = json.loads(response.text)
            return schema.model_validate(parsed_json)
        except Exception as e:
            logger.warning(f"Gemini structured response generation error: {e}")
            return None

    def generate_text(
        self, prompt: str, system_instruction: str = ""
    ) -> Optional[str]:
        client = self._get_client()
        if not client:
            return None
        try:
            from google.genai import types
            config = types.GenerateContentConfig(
                system_instruction=system_instruction if system_instruction else None,
                temperature=0.1,
            )
            response = client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=config,
            )
            if response and response.text:
                return response.text
            return None
        except Exception as e:
            logger.warning(f"Gemini text generation error: {e}")
            return None


class AnthropicLLMProvider(BaseLLMProvider):
    """Anthropic Claude LLM Provider stub."""

    def generate_structured_response(
        self, prompt: str, schema: Type[BaseModel], system_instruction: str = ""
    ) -> Optional[BaseModel]:
        logger.warning("AnthropicLLMProvider structured generation is not configured.")
        return None

    def generate_text(
        self, prompt: str, system_instruction: str = ""
    ) -> Optional[str]:
        logger.warning("AnthropicLLMProvider text generation is not configured.")
        return None


def get_llm_client(provider: Optional[str] = None) -> BaseLLMProvider:
    """Factory function to retrieve configured LLM provider abstraction."""
    selected_provider = (provider or getattr(settings, "LLM_PROVIDER", "gemini")).lower()
    if selected_provider == "anthropic":
        return AnthropicLLMProvider()
    return GeminiLLMProvider()
