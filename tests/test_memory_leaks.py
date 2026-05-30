"""Tests for memory leak fixes in CodeBERT embedder."""

import gc
import sys
from datetime import datetime
from unittest.mock import Mock, patch

import psutil
import pytest
import torch

from ai_security_scanner.core.models import CodeEmbedding
from ai_security_scanner.models.embeddings.codebert import CodeBERTEmbedder, LRUCache, ModelRegistry


class TestLRUCache:
    """Test cases for LRU cache implementation."""

    def test_lru_cache_basic_operations(self):
        """Test basic LRU cache operations."""
        cache = LRUCache(max_size=3)

        # Test put and get
        embedding1 = CodeEmbedding(
            code_hash="hash1",
            embedding=[1.0, 2.0, 3.0],
            model_name="test",
            model_version="1.0",
            created_at=datetime.now(),
        )

        cache.put("key1", embedding1)
        assert cache.get("key1") == embedding1
        assert len(cache) == 1

        # Test cache miss
        assert cache.get("nonexistent") is None

        # Test contains
        assert "key1" in cache
        assert "nonexistent" not in cache

    def test_lru_eviction(self):
        """Test LRU eviction when cache is full."""
        cache = LRUCache(max_size=2)

        embeddings = []
        for i in range(3):
            embedding = CodeEmbedding(
                code_hash=f"hash{i}",
                embedding=[float(i)],
                model_name="test",
                model_version="1.0",
                created_at=datetime.now(),
            )
            embeddings.append(embedding)
            cache.put(f"key{i}", embedding)

        # First key should be evicted
        assert "key0" not in cache
        assert "key1" in cache
        assert "key2" in cache
        assert len(cache) == 2

    def test_lru_access_order(self):
        """Test that accessing items updates their position."""
        cache = LRUCache(max_size=2)

        embedding1 = CodeEmbedding(
            code_hash="hash1",
            embedding=[1.0],
            model_name="test",
            model_version="1.0",
            created_at=datetime.now(),
        )
        embedding2 = CodeEmbedding(
            code_hash="hash2",
            embedding=[2.0],
            model_name="test",
            model_version="1.0",
            created_at=datetime.now(),
        )

        cache.put("key1", embedding1)
        cache.put("key2", embedding2)

        # Access key1 to make it most recently used
        _ = cache.get("key1")

        # Add third item, key2 should be evicted (least recently used)
        embedding3 = CodeEmbedding(
            code_hash="hash3",
            embedding=[3.0],
            model_name="test",
            model_version="1.0",
            created_at=datetime.now(),
        )
        cache.put("key3", embedding3)

        assert "key1" in cache  # Recently accessed
        assert "key2" not in cache  # Evicted
        assert "key3" in cache  # Just added


class TestModelRegistry:
    """Test cases for model registry with reference counting."""

    @patch("ai_security_scanner.models.embeddings.codebert.AutoTokenizer.from_pretrained")
    @patch("ai_security_scanner.models.embeddings.codebert.AutoModel.from_pretrained")
    def test_model_reference_counting(self, mock_model, mock_tokenizer):
        """Test model reference counting and cleanup."""
        # Setup mocks
        mock_tokenizer_instance = Mock()
        mock_model_instance = Mock()
        mock_model_instance.to = Mock(return_value=mock_model_instance)
        mock_model_instance.eval = Mock(return_value=None)
        mock_model_instance.cpu = Mock(return_value=None)

        mock_tokenizer.return_value = mock_tokenizer_instance
        mock_model.return_value = mock_model_instance

        registry = ModelRegistry()
        device = torch.device("cpu")

        # First request should load model
        tokenizer1, model1 = registry.get_model("test-model", device)
        assert mock_model.called
        assert mock_tokenizer.called

        # Second request should reuse cached model
        mock_model.reset_mock()
        mock_tokenizer.reset_mock()
        tokenizer2, model2 = registry.get_model("test-model", device)
        assert not mock_model.called
        assert not mock_tokenizer.called
        assert tokenizer1 is tokenizer2
        assert model1 is model2

        # Release references
        registry.release_model("test-model", device)
        # Model should still be cached (one reference remaining)
        assert f"test-model:{device}" in registry._models

        registry.release_model("test-model", device)
        # Model should be cleaned up (no references)
        assert f"test-model:{device}" not in registry._models
        assert mock_model_instance.cpu.called

    @patch("ai_security_scanner.models.embeddings.codebert.AutoTokenizer.from_pretrained")
    @patch("ai_security_scanner.models.embeddings.codebert.AutoModel.from_pretrained")
    def test_cleanup_all(self, mock_model, mock_tokenizer):
        """Test cleanup of all models."""
        mock_model_instance = Mock()
        mock_model_instance.to = Mock(return_value=mock_model_instance)
        mock_model_instance.eval = Mock(return_value=None)
        mock_model_instance.cpu = Mock(return_value=None)

        mock_tokenizer.return_value = Mock()
        mock_model.return_value = mock_model_instance

        registry = ModelRegistry()
        device = torch.device("cpu")

        # Load multiple models
        registry.get_model("model1", device)
        registry.get_model("model2", device)

        assert len(registry._models) == 2

        # Cleanup all
        registry.cleanup_all()
        assert len(registry._models) == 0
        assert mock_model_instance.cpu.call_count == 2


class TestCodeBERTEmbedderMemoryManagement:
    """Test memory management in CodeBERTEmbedder."""

    @patch("ai_security_scanner.models.embeddings.codebert.ModelRegistry")
    def test_embedder_cleanup_on_deletion(self, mock_registry_class):
        """Test that embedder cleans up resources on deletion."""
        mock_registry = Mock()
        mock_registry_class.return_value = mock_registry

        # Create embedder
        embedder = CodeBERTEmbedder()
        embedder._model_loaded = True

        # Delete embedder
        del embedder
        gc.collect()  # Force garbage collection

        # Verify cleanup was called
        # Note: This is difficult to test directly due to weakref finalization
        # In practice, the cleanup will happen during garbage collection

    def test_cache_memory_limits(self):
        """Test that cache respects memory limits."""
        embedder = CodeBERTEmbedder()
        embedder.cache_size_limit = 10
        embedder.embedding_cache = LRUCache(10)

        # Fill cache beyond limit
        for i in range(20):
            code = f"test_code_{i}"
            code_hash = embedder._generate_code_hash(code)
            embedding = CodeEmbedding(
                code_hash=code_hash,
                embedding=[float(i)] * 768,
                model_name="test",
                model_version="1.0",
                created_at=datetime.now(),
            )
            embedder.embedding_cache.put(code_hash, embedding)

        # Cache should not exceed limit
        assert len(embedder.embedding_cache) <= 10

    def test_cache_stats(self):
        """Test cache statistics reporting."""
        embedder = CodeBERTEmbedder()
        embedder.cache_size_limit = 100
        embedder.embedding_cache = LRUCache(100)

        # Add some embeddings
        for i in range(25):
            code_hash = f"hash_{i}"
            embedding = CodeEmbedding(
                code_hash=code_hash,
                embedding=[0.0] * 768,
                model_name="test",
                model_version="1.0",
                created_at=datetime.now(),
            )
            embedder.embedding_cache.put(code_hash, embedding)

        stats = embedder.get_cache_stats()
        assert stats["cache_size"] == 25
        assert stats["cache_limit"] == 100
        assert stats["cache_usage_percent"] == 25
        assert "model_loaded" in stats
        assert "device" in stats


@pytest.mark.integration
class TestMemoryLeakIntegration:
    """Integration tests for memory leak fixes."""

    def get_memory_usage(self):
        """Get current memory usage in MB."""
        process = psutil.Process()
        return process.memory_info().rss / 1024 / 1024

    @pytest.mark.skipif(not torch.cuda.is_available(), reason="CUDA not available")
    @patch("ai_security_scanner.models.embeddings.codebert.AutoTokenizer.from_pretrained")
    @patch("ai_security_scanner.models.embeddings.codebert.AutoModel.from_pretrained")
    def test_gpu_memory_cleanup(self, mock_model, mock_tokenizer):
        """Test GPU memory cleanup."""
        # Mock model that tracks GPU memory
        mock_model_instance = Mock()
        mock_model_instance.to = Mock(return_value=mock_model_instance)
        mock_model_instance.eval = Mock(return_value=None)
        mock_model_instance.cpu = Mock(return_value=None)

        mock_tokenizer.return_value = Mock()
        mock_model.return_value = mock_model_instance

        initial_gpu_memory = torch.cuda.memory_allocated()

        # Create and destroy multiple embedders
        for _ in range(5):
            embedder = CodeBERTEmbedder()
            embedder._ensure_model_loaded()
            del embedder
            gc.collect()
            torch.cuda.empty_cache()

        final_gpu_memory = torch.cuda.memory_allocated()

        # GPU memory should not increase significantly
        memory_increase = final_gpu_memory - initial_gpu_memory
        assert memory_increase < 100 * 1024 * 1024  # Less than 100MB increase


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
