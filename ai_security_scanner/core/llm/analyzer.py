"""LLM-powered reliability finding analyzer."""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from ai_security_scanner.core.config import Config
from ai_security_scanner.core.llm.providers import LLMProvider, create_llm_provider
from ai_security_scanner.core.models import Confidence, Severity, VulnerabilityResult
from ai_security_scanner.models.embeddings.codebert import CodeBERTEmbedder

logger = logging.getLogger(__name__)


class VulnerabilityAnalyzer:
    """LLM-powered reliability analyzer for enhanced detection and false positive reduction."""

    def __init__(self, config: Optional[Config] = None):
        """Initialize reliability analyzer.

        Args:
            config: Configuration object
        """
        self.config = config or Config.from_env()
        self.llm_provider: Optional[LLMProvider] = None
        self.embedder: Optional[CodeBERTEmbedder] = None
        self._ai_components_initialized = False

    def _initialize_ai_components(self) -> None:
        """Initialize AI components (LLM and embeddings)."""
        if self._ai_components_initialized:
            return

        try:
            # Initialize LLM provider
            self.llm_provider = create_llm_provider(self.config)
            logger.info(f"Initialized LLM provider: {self.config.llm.provider}")

            # Initialize embeddings
            self.embedder = CodeBERTEmbedder(self.config)
            logger.info("Initialized CodeBERT embedder")

            self._ai_components_initialized = True

        except Exception as e:
            logger.error(f"Error initializing AI components: {e}")
            self.llm_provider = None
            self.embedder = None
            raise

    async def analyze_vulnerabilities(
        self, vulnerabilities: List[VulnerabilityResult], source_code: str, context: Dict[str, Any]
    ) -> List[VulnerabilityResult]:
        """Analyze findings with LLM enhancement.

        Args:
            vulnerabilities: List of detected reliability findings
            source_code: Full source code for context
            context: Additional context information

        Returns:
            Enhanced reliability findings
        """
        if not self.config.scanner.enable_ai_analysis:
            return vulnerabilities

        # Initialize AI components when needed
        if not self._ai_components_initialized:
            try:
                self._initialize_ai_components()
            except Exception as e:
                logger.warning(f"Failed to initialize AI components: {e}")
                return vulnerabilities

        if not self.llm_provider:
            return vulnerabilities

        enhanced_vulnerabilities = []

        # Process findings concurrently with limited batch size
        batch_size = 5  # Limit concurrent LLM requests
        for i in range(0, len(vulnerabilities), batch_size):
            batch = vulnerabilities[i : i + batch_size]

            # Process batch concurrently
            tasks = [
                self._analyze_single_vulnerability(vuln, source_code, context) for vuln in batch
            ]

            enhanced_batch = await asyncio.gather(*tasks, return_exceptions=True)

            # Handle results and exceptions
            for result in enhanced_batch:
                if isinstance(result, Exception):
                    logger.error(f"Error in reliability analysis: {result}")
                    continue
                if result:  # Only add non-None results
                    enhanced_vulnerabilities.append(result)

        return enhanced_vulnerabilities

    async def _analyze_single_vulnerability(
        self, vulnerability: VulnerabilityResult, source_code: str, context: Dict[str, Any]
    ) -> Optional[VulnerabilityResult]:
        """Analyze a single finding with LLM.

        Args:
            vulnerability: Finding to analyze
            source_code: Full source code
            context: Additional context

        Returns:
            Enhanced finding result or None if filtered out
        """
        try:
            # Extract code snippet around finding
            code_snippet = self._extract_code_snippet(
                source_code, vulnerability.location.line_number, context_lines=10
            )

            # Prepare context for LLM
            llm_context = {
                **context,
                "original_detection": {
                    "type": vulnerability.vulnerability_type,
                    "severity": vulnerability.severity.value,
                    "confidence": vulnerability.confidence.value,
                    "description": vulnerability.description,
                },
                "code_location": {
                    "file_path": vulnerability.location.file_path,
                    "line_number": vulnerability.location.line_number,
                },
            }

            # Get LLM analysis
            analysis = await self.llm_provider.analyze_vulnerability(
                code_snippet, vulnerability.vulnerability_type, llm_context
            )

            # Check for false positive
            false_positive_check = await self.llm_provider.check_false_positive(
                code_snippet, vulnerability.description, llm_context
            )

            # Combine analyses
            enhanced_vulnerability = self._enhance_vulnerability_with_analysis(
                vulnerability, analysis, false_positive_check
            )

            # Filter out likely false positives
            if self.config.scanner.false_positive_reduction:
                if (
                    enhanced_vulnerability.false_positive_likelihood
                    and enhanced_vulnerability.false_positive_likelihood > 0.8
                ):
                    logger.info(
                        "Filtering out likely false positive: "
                        f"{vulnerability.vulnerability_type} at "
                        f"{vulnerability.location.file_path}:"
                        f"{vulnerability.location.line_number}"
                    )
                    return None

            return enhanced_vulnerability

        except Exception as e:
            logger.error(f"Error analyzing finding {vulnerability.id}: {e}")
            return vulnerability  # Return original finding if analysis fails

    def _extract_code_snippet(
        self, source_code: str, line_number: int, context_lines: int = 5
    ) -> str:
        """Extract code snippet with context around the finding.

        Args:
            source_code: Full source code
            line_number: Line number of finding
            context_lines: Number of context lines to include

        Returns:
            Code snippet with context
        """
        lines = source_code.split("\n")
        start_line = max(0, line_number - context_lines - 1)
        end_line = min(len(lines), line_number + context_lines)

        snippet_lines = []
        for i in range(start_line, end_line):
            line_num = i + 1
            prefix = ">>> " if line_num == line_number else "    "
            snippet_lines.append(f"{prefix}{line_num:4d}: {lines[i]}")

        return "\n".join(snippet_lines)

    def _enhance_vulnerability_with_analysis(
        self,
        vulnerability: VulnerabilityResult,
        analysis: Dict[str, Any],
        false_positive_check: Dict[str, Any],
    ) -> VulnerabilityResult:
        """Enhance finding with LLM analysis results.

        Args:
            vulnerability: Original finding
            analysis: LLM analysis results
            false_positive_check: False positive check results

        Returns:
            Enhanced finding result
        """
        # Create enhanced finding copy
        enhanced = VulnerabilityResult(
            id=vulnerability.id,
            vulnerability_type=vulnerability.vulnerability_type,
            title=vulnerability.title,
            description=vulnerability.description,
            severity=vulnerability.severity,
            confidence=vulnerability.confidence,
            location=vulnerability.location,
            code_snippet=vulnerability.code_snippet,
            cwe_id=vulnerability.cwe_id,
            owasp_category=vulnerability.owasp_category,
            remediation=vulnerability.remediation,
            references=vulnerability.references,
            metadata=vulnerability.metadata.copy(),
        )

        # Add LLM analysis
        enhanced.ai_explanation = analysis.get("analysis", "")
        enhanced.false_positive_likelihood = false_positive_check.get(
            "false_positive_likelihood", 0.5
        )

        # Update severity if LLM provides different assessment
        llm_severity = analysis.get("severity_assessment", "").upper()
        if llm_severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            enhanced.severity = Severity(llm_severity)

        # Update confidence based on LLM confidence
        llm_confidence = analysis.get("confidence", "").upper()
        if llm_confidence in ["LOW", "MEDIUM", "HIGH"]:
            enhanced.confidence = Confidence(llm_confidence)

        # Update remediation if LLM provides better advice
        llm_remediation = analysis.get("remediation", "")
        if llm_remediation and len(llm_remediation) > len(enhanced.remediation or ""):
            enhanced.remediation = llm_remediation

        # Add LLM metadata
        enhanced.metadata.update(
            {
                "llm_analysis": {
                    "provider": self.config.llm.provider,
                    "model": self.config.llm.model,
                    "analysis_timestamp": datetime.now().isoformat(),
                    "failure_scenarios": analysis.get(
                        "failure_scenarios", analysis.get("attack_vectors", [])
                    ),
                    "impact": analysis.get("impact", ""),
                    "false_positive_likelihood": enhanced.false_positive_likelihood,
                    "llm_confidence": analysis.get("confidence", "UNKNOWN"),
                }
            }
        )

        return enhanced

    def analyze_code_patterns(self, code: str, language: str) -> Dict[str, Any]:
        """Analyze code patterns using embeddings.

        Args:
            code: Source code to analyze
            language: Programming language

        Returns:
            Code pattern analysis results
        """
        if not self.embedder:
            return {}

        try:
            return self.embedder.analyze_code_patterns(code, language)
        except Exception as e:
            logger.error(f"Error in code pattern analysis: {e}")
            return {}

    def find_similar_vulnerabilities(
        self,
        target_vulnerability: VulnerabilityResult,
        all_vulnerabilities: List[VulnerabilityResult],
        threshold: float = 0.8,
    ) -> List[VulnerabilityResult]:
        """Find similar findings using embeddings.

        Args:
            target_vulnerability: Target finding to find similarities for
            all_vulnerabilities: All findings to search through
            threshold: Similarity threshold

        Returns:
            List of similar findings
        """
        if not self.embedder:
            return []

        try:
            # Get code snippets
            target_code = target_vulnerability.code_snippet
            other_codes = [
                vuln.code_snippet
                for vuln in all_vulnerabilities
                if vuln.id != target_vulnerability.id
            ]

            # Find similar code snippets
            similar_codes = self.embedder.find_similar_code(
                target_code, other_codes, threshold=threshold
            )

            # Map back to findings
            similar_vulnerabilities = []
            for similar_code, similarity_score in similar_codes:
                for vuln in all_vulnerabilities:
                    if vuln.code_snippet == similar_code:
                        # Add similarity score to metadata
                        vuln.metadata["similarity_score"] = similarity_score
                        similar_vulnerabilities.append(vuln)
                        break

            return similar_vulnerabilities

        except Exception as e:
            logger.error(f"Error finding similar findings: {e}")
            return []

    def get_analysis_stats(self) -> Dict[str, Any]:
        """Get analysis statistics.

        Returns:
            Dictionary with analysis statistics
        """
        stats = {
            "ai_analysis_enabled": self.config.scanner.enable_ai_analysis,
            "llm_provider": self.config.llm.provider if self.llm_provider else None,
            "embedder_available": self.embedder is not None,
            "false_positive_reduction": self.config.scanner.false_positive_reduction,
        }

        if self.embedder:
            stats["embedding_cache_stats"] = self.embedder.get_cache_stats()

        return stats
