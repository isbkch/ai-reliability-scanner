"""LLM providers for reliability finding analysis."""

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from ai_security_scanner.core.config import Config

logger = logging.getLogger(__name__)


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    def __init__(self, config: Config):
        """Initialize LLM provider.

        Args:
            config: Configuration object
        """
        self.config = config
        self.last_request_time = 0
        self.request_count = 0
        self.rate_limit_delay = 60.0 / config.llm.rate_limit_requests_per_minute

    @abstractmethod
    async def analyze_vulnerability(
        self, code: str, vulnerability_type: str, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze finding and provide explanation.

        Args:
            code: Source code snippet
            vulnerability_type: Type of finding
            context: Additional context information

        Returns:
            Analysis result dictionary
        """
        pass

    @abstractmethod
    async def check_false_positive(
        self, code: str, vulnerability_description: str, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check if a finding is a false positive.

        Args:
            code: Source code snippet
            vulnerability_description: Description of the finding
            context: Additional context information

        Returns:
            False positive analysis result
        """
        pass

    async def _enforce_rate_limit(self) -> None:
        """Enforce rate limiting."""
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time

        if time_since_last_request < self.rate_limit_delay:
            sleep_time = self.rate_limit_delay - time_since_last_request
            await asyncio.sleep(sleep_time)

        self.last_request_time = time.time()
        self.request_count += 1

    def _create_system_prompt(self) -> str:
        """Create system prompt for reliability finding analysis."""
        return """You are a production reliability expert reviewing generated service code.

Your role is to:
1. Analyze code snippets for production-readiness and reliability risks
2. Provide clear, actionable explanations of operational failure modes
3. Suggest specific remediation steps
4. Assess whether detected issues are false positives
5. Consider the context and real-world impact of reliability risks

Guidelines:
- Be precise and technical in your analysis
- Focus on actionable reliability advice
- Consider deploy, dependency, load, retry, and incident behavior
- Explain the potential outage modes and customer impact
- Provide specific code examples for remediation when possible
- Be honest about uncertainty - if you're not sure, say so

Response format should be JSON with the following structure:
{
    "analysis": "detailed analysis of the reliability risk",
    "severity_assessment": "LOW|MEDIUM|HIGH|CRITICAL",
    "false_positive_likelihood": 0.0-1.0,
    "remediation": "specific steps to fix the issue",
    "failure_scenarios": ["list of potential outage or degradation scenarios"],
    "impact": "description of potential impact",
    "confidence": "LOW|MEDIUM|HIGH"
}"""

    def _create_vulnerability_analysis_prompt(
        self, code: str, vulnerability_type: str, context: Dict[str, Any]
    ) -> str:
        """Create prompt for reliability finding analysis.

        Args:
            code: Source code snippet
            vulnerability_type: Type of finding
            context: Additional context

        Returns:
            Analysis prompt
        """
        language = context.get("language", "unknown")
        file_path = context.get("file_path", "unknown")

        return f"""Analyze this code snippet for a potential {vulnerability_type} reliability risk:

**Code (Language: {language}):**
```{language}
{code}
```

**File Path:** {file_path}

**Context:**
{self._format_context(context)}

**Finding Type:** {vulnerability_type}

Please provide a detailed analysis focusing on:
1. Whether this is actually a production-readiness risk
2. The severity and potential impact
3. Specific outage or degradation scenarios
4. Exact remediation steps with code examples
5. Your confidence level in this assessment

Be especially careful to avoid false positives - consider whether the code has equivalent
reliability controls elsewhere in scope."""

    def _create_false_positive_check_prompt(
        self, code: str, vulnerability_description: str, context: Dict[str, Any]
    ) -> str:
        """Create prompt for false positive checking.

        Args:
            code: Source code snippet
            vulnerability_description: Description of finding
            context: Additional context

        Returns:
            False positive check prompt
        """
        language = context.get("language", "unknown")

        return f"""Review this potential reliability finding and assess if it's a false positive:

**Code (Language: {language}):**
```{language}
{code}
```

**Finding Description:** {vulnerability_description}

**Context:**
{self._format_context(context)}

Please analyze whether this is a false positive by considering:
1. Is the code actually risky in a real-world production scenario?
2. Are there mitigating controls that prevent outage or degradation?
3. Is the risky code path actually reachable under production load?
4. Are there timeouts, backpressure, shutdown, or observability controls nearby?
5. Is this a test file or example code?

Provide your assessment with a confidence score and detailed reasoning."""

    def _format_context(self, context: Dict[str, Any]) -> str:
        """Format context information for prompts.

        Args:
            context: Context dictionary

        Returns:
            Formatted context string
        """
        formatted_lines = []

        for key, value in context.items():
            if key in ["language", "file_path"]:
                continue  # These are handled separately

            if isinstance(value, (list, dict)):
                formatted_lines.append(f"- {key}: {str(value)}")
            else:
                formatted_lines.append(f"- {key}: {value}")

        return "\n".join(formatted_lines) if formatted_lines else "No additional context provided"


class OpenAIProvider(LLMProvider):
    """OpenAI GPT provider for reliability analysis."""

    def __init__(self, config: Config):
        """Initialize OpenAI provider.

        Args:
            config: Configuration object
        """
        super().__init__(config)

        try:
            import openai

            self.client = openai.AsyncOpenAI(
                api_key=config.get_api_key(config.llm.api_key_env),
                base_url=config.llm.api_base_url,
                timeout=config.llm.timeout,
            )
        except ImportError:
            raise ImportError("OpenAI library not installed. Run: pip install openai")

    async def analyze_vulnerability(
        self, code: str, vulnerability_type: str, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze finding using OpenAI GPT.

        Args:
            code: Source code snippet
            vulnerability_type: Type of finding
            context: Additional context information

        Returns:
            Analysis result dictionary
        """
        await self._enforce_rate_limit()

        try:
            system_prompt = self._create_system_prompt()
            user_prompt = self._create_vulnerability_analysis_prompt(
                code, vulnerability_type, context
            )

            response = await self.client.chat.completions.create(
                model=self.config.llm.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=self.config.llm.temperature,
                max_tokens=self.config.llm.max_tokens,
                response_format={"type": "json_object"},
            )

            result = response.choices[0].message.content

            # Parse JSON response
            import json

            return json.loads(result)

        except Exception as e:
            logger.error(f"Error in OpenAI reliability analysis: {e}")
            return self._create_error_response(str(e))

    async def check_false_positive(
        self, code: str, vulnerability_description: str, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check false positive using OpenAI GPT.

        Args:
            code: Source code snippet
            vulnerability_description: Description of finding
            context: Additional context information

        Returns:
            False positive analysis result
        """
        await self._enforce_rate_limit()

        try:
            system_prompt = self._create_system_prompt()
            user_prompt = self._create_false_positive_check_prompt(
                code, vulnerability_description, context
            )

            response = await self.client.chat.completions.create(
                model=self.config.llm.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=self.config.llm.temperature,
                max_tokens=self.config.llm.max_tokens,
                response_format={"type": "json_object"},
            )

            result = response.choices[0].message.content

            # Parse JSON response
            import json

            return json.loads(result)

        except Exception as e:
            logger.error(f"Error in OpenAI false positive check: {e}")
            return self._create_error_response(str(e))

    def _create_error_response(self, error_message: str) -> Dict[str, Any]:
        """Create error response.

        Args:
            error_message: Error message

        Returns:
            Error response dictionary
        """
        return {
            "analysis": f"Error in LLM analysis: {error_message}",
            "severity_assessment": "UNKNOWN",
            "false_positive_likelihood": 0.5,
            "remediation": "Unable to provide remediation due to analysis error",
            "failure_scenarios": [],
            "impact": "Unknown due to analysis error",
            "confidence": "LOW",
            "error": error_message,
        }


class AnthropicProvider(LLMProvider):
    """Anthropic Claude provider for reliability analysis."""

    def __init__(self, config: Config):
        """Initialize Anthropic provider.

        Args:
            config: Configuration object
        """
        super().__init__(config)

        try:
            import anthropic

            self.client = anthropic.AsyncAnthropic(
                api_key=config.get_api_key(config.llm.api_key_env), timeout=config.llm.timeout
            )
        except ImportError:
            raise ImportError("Anthropic library not installed. Run: pip install anthropic")

    async def analyze_vulnerability(
        self, code: str, vulnerability_type: str, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze finding using Anthropic Claude.

        Args:
            code: Source code snippet
            vulnerability_type: Type of finding
            context: Additional context information

        Returns:
            Analysis result dictionary
        """
        await self._enforce_rate_limit()

        try:
            system_prompt = self._create_system_prompt()
            user_prompt = self._create_vulnerability_analysis_prompt(
                code, vulnerability_type, context
            )

            response = await self.client.messages.create(
                model=self.config.llm.model,
                max_tokens=self.config.llm.max_tokens,
                temperature=self.config.llm.temperature,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
            )

            result = response.content[0].text

            # Parse JSON response
            import json

            return json.loads(result)

        except Exception as e:
            logger.error(f"Error in Anthropic reliability analysis: {e}")
            return self._create_error_response(str(e))

    async def check_false_positive(
        self, code: str, vulnerability_description: str, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check false positive using Anthropic Claude.

        Args:
            code: Source code snippet
            vulnerability_description: Description of finding
            context: Additional context information

        Returns:
            False positive analysis result
        """
        await self._enforce_rate_limit()

        try:
            system_prompt = self._create_system_prompt()
            user_prompt = self._create_false_positive_check_prompt(
                code, vulnerability_description, context
            )

            response = await self.client.messages.create(
                model=self.config.llm.model,
                max_tokens=self.config.llm.max_tokens,
                temperature=self.config.llm.temperature,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
            )

            result = response.content[0].text

            # Parse JSON response
            import json

            return json.loads(result)

        except Exception as e:
            logger.error(f"Error in Anthropic false positive check: {e}")
            return self._create_error_response(str(e))

    def _create_error_response(self, error_message: str) -> Dict[str, Any]:
        """Create error response.

        Args:
            error_message: Error message

        Returns:
            Error response dictionary
        """
        return {
            "analysis": f"Error in LLM analysis: {error_message}",
            "severity_assessment": "UNKNOWN",
            "false_positive_likelihood": 0.5,
            "remediation": "Unable to provide remediation due to analysis error",
            "failure_scenarios": [],
            "impact": "Unknown due to analysis error",
            "confidence": "LOW",
            "error": error_message,
        }


def create_llm_provider(config: Config) -> LLMProvider:
    """Create LLM provider based on configuration.

    Args:
        config: Configuration object

    Returns:
        LLM provider instance
    """
    provider_name = config.llm.provider.lower()

    if provider_name == "openai":
        return OpenAIProvider(config)
    elif provider_name == "anthropic":
        return AnthropicProvider(config)
    else:
        raise ValueError(f"Unsupported LLM provider: {provider_name}")
