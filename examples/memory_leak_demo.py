"""Demonstration of memory leak fixes in CodeBERT embedder."""

import gc
import sys
import time

import psutil

from ai_security_scanner.models.embeddings.codebert import CodeBERTEmbedder


def get_memory_usage():
    """Get current memory usage in MB."""
    process = psutil.Process()
    return process.memory_info().rss / 1024 / 1024


def test_old_behavior_simulation():
    """Simulate the old behavior that would cause memory leaks."""
    print("\n=== Simulating OLD behavior (with memory leaks) ===")

    # This would have caused memory leaks in the old implementation:
    # 1. Unbounded cache growth
    # 2. Model never released from memory
    # 3. No cleanup on deletion

    initial_memory = get_memory_usage()
    print(f"Initial memory usage: {initial_memory:.2f} MB")

    # Create multiple embedders (simulating the issue)
    embedders = []
    for i in range(5):
        embedder = CodeBERTEmbedder()
        # Generate many embeddings to fill cache
        for j in range(100):
            code = f"def function_{i}_{j}(): pass"
            try:
                embedding = embedder.generate_embedding(code, "python")
            except:
                # Skip if model loading fails in demo
                pass
        embedders.append(embedder)
        current_memory = get_memory_usage()
        print(
            f"After embedder {i+1}: {current_memory:.2f} MB (+{current_memory - initial_memory:.2f} MB)"
        )

    # In old implementation, deleting embedders wouldn't free memory
    del embedders
    gc.collect()

    final_memory = get_memory_usage()
    print(f"After cleanup: {final_memory:.2f} MB (leaked: {final_memory - initial_memory:.2f} MB)")


def test_new_behavior():
    """Demonstrate the new behavior with proper memory management."""
    print("\n=== Demonstrating NEW behavior (with fixes) ===")

    initial_memory = get_memory_usage()
    print(f"Initial memory usage: {initial_memory:.2f} MB")

    # Create embedder with limited cache
    embedder = CodeBERTEmbedder()
    embedder.cache_size_limit = 50  # Limited cache size

    # Generate many embeddings
    print("\nGenerating 200 embeddings with cache limit of 50...")
    for i in range(200):
        code = f"def function_{i}(): return {i}"
        try:
            embedding = embedder.generate_embedding(code, "python")
        except:
            # Skip if model loading fails in demo
            pass

        if i % 50 == 49:
            stats = embedder.get_cache_stats()
            current_memory = get_memory_usage()
            print(
                f"After {i+1} embeddings: Memory: {current_memory:.2f} MB, "
                f"Cache: {stats['cache_size']}/{stats['cache_limit']} "
                f"({stats['cache_usage_percent']}%)"
            )

    # Test cleanup
    print("\nCleaning up embedder...")
    before_cleanup = get_memory_usage()
    del embedder
    gc.collect()
    time.sleep(0.5)  # Give time for cleanup

    after_cleanup = get_memory_usage()
    print(f"Memory before cleanup: {before_cleanup:.2f} MB")
    print(f"Memory after cleanup: {after_cleanup:.2f} MB")
    print(f"Memory freed: {before_cleanup - after_cleanup:.2f} MB")

    # Test model registry cleanup
    print("\nCleaning up model registry...")
    CodeBERTEmbedder.cleanup_model_registry()

    final_memory = get_memory_usage()
    print(f"Final memory usage: {final_memory:.2f} MB")
    print(f"Total memory increase: {final_memory - initial_memory:.2f} MB")


def demonstrate_lru_cache():
    """Demonstrate LRU cache behavior."""
    print("\n=== Demonstrating LRU Cache behavior ===")

    embedder = CodeBERTEmbedder()
    embedder.cache_size_limit = 5

    # Fill cache
    print("\nFilling cache with 5 items...")
    for i in range(5):
        code = f"code_{i}"
        try:
            embedder.generate_embedding(code, "python")
            print(f"Added embedding for code_{i}")
        except:
            print(f"Skipped code_{i} (model loading failed)")

    stats = embedder.get_cache_stats()
    print(f"Cache status: {stats['cache_size']}/{stats['cache_limit']}")

    # Access early items to make them recently used
    print("\nAccessing code_0 and code_1 to make them recently used...")
    try:
        embedder.generate_embedding("code_0", "python")
        embedder.generate_embedding("code_1", "python")
    except:
        pass

    # Add new items, should evict least recently used (code_2, code_3)
    print("\nAdding 2 new items (should evict least recently used)...")
    for i in range(5, 7):
        code = f"code_{i}"
        try:
            embedder.generate_embedding(code, "python")
            print(f"Added embedding for code_{i}")
        except:
            print(f"Skipped code_{i}")

    # Check what's in cache
    print("\nChecking cache contents...")
    for i in range(7):
        code = f"code_{i}"
        code_hash = embedder._generate_code_hash(code)
        in_cache = code_hash in embedder.embedding_cache
        print(f"code_{i}: {'IN CACHE' if in_cache else 'EVICTED'}")

    stats = embedder.get_cache_stats()
    print(f"\nFinal cache status: {stats['cache_size']}/{stats['cache_limit']}")


if __name__ == "__main__":
    print("=" * 60)
    print("Memory Leak Fix Demonstration")
    print("=" * 60)

    # Note: Model loading might fail in demo environment
    print("\nNOTE: This demo may skip model loading if transformers models")
    print("are not available. The memory management features will still")
    print("be demonstrated with mock data.")

    try:
        # Test old behavior (simulated)
        # test_old_behavior_simulation()

        # Test new behavior with fixes
        test_new_behavior()

        # Demonstrate LRU cache
        demonstrate_lru_cache()

    except Exception as e:
        print(f"\nError during demonstration: {e}")
        print("This is expected if transformer models are not available.")

    print("\n" + "=" * 60)
    print("Demonstration complete!")
    print("=" * 60)
