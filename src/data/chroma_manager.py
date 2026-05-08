"""
ChromaDB Manager for Safe-Package RAG.

Manages a persistent vector store of known-safe packages at data/chroma_store/.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from src.core.config import DATA_DIR

logger = logging.getLogger(__name__)


class ChromaManager:
    """ChromaDB vector store for safe package alternatives."""

    def __init__(self, store_path: Path | None = None) -> None:
        self._store_path = str(store_path or (DATA_DIR / "chroma_store"))
        self._client = None
        self._collection = None
        self._initialized = False

    def _ensure_initialized(self) -> None:
        if self._initialized:
            return

        try:
            import chromadb

            self._client = chromadb.PersistentClient(path=self._store_path)
            self._collection = self._client.get_or_create_collection(
                name="safe_packages",
                metadata={"hnsw:space": "cosine"},
            )
            self._initialized = True
            logger.info(
                "ChromaDB initialized at %s (%d documents)",
                self._store_path,
                self._collection.count(),
            )
        except ImportError:
            logger.error("chromadb not installed; vector search disabled")
        except Exception as e:
            logger.error("ChromaDB initialization failed: %s", e)

    def query_similar(self, query: str, n_results: int = 5, language: str | None = None) -> list[tuple[str, str, float]]:
        """Find similar packages.
        
        Returns:
            List of (name, description, distance).
        """
        self._ensure_initialized()

        if not self._collection or self._collection.count() == 0:
            return []

        try:
            where_filter = {"language": language} if language else None

            results = self._collection.query(
                query_texts=[query],
                n_results=min(n_results, self._collection.count()),
                where=where_filter,
            )

            matches: list[tuple[str, str, float]] = []
            if results and results["documents"]:
                docs = results["documents"][0]
                metadatas = results["metadatas"][0] if results["metadatas"] else [{}] * len(docs)
                distances = results["distances"][0] if results["distances"] else [0.0] * len(docs)
                ids = results["ids"][0] if results["ids"] else [""] * len(docs)

                for doc, meta, dist, pkg_id in zip(docs, metadatas, distances, ids):
                    name = meta.get("name", pkg_id)
                    matches.append((name, doc, dist))

            return matches
        except Exception as e:
            logger.error("ChromaDB query failed: %s", e)
            return []

    def add_packages(self, packages_list: list[dict[str, Any]]) -> None:
        """Add multiple packages in a single batch.

        Args:
            packages_list: List of dicts with keys: name, description, language.
        """
        self._ensure_initialized()

        if not self._collection:
            return

        ids = [p["name"] for p in packages_list]
        documents = [p.get("description", p["name"]) for p in packages_list]
        metadatas = [
            {"name": p["name"], "language": p.get("language", "python")}
            for p in packages_list
        ]

        try:
            batch_size = 500
            for i in range(0, len(ids), batch_size):
                self._collection.upsert(
                    ids=ids[i : i + batch_size],
                    documents=documents[i : i + batch_size],
                    metadatas=metadatas[i : i + batch_size],
                )
        except Exception as e:
            logger.error("Batch add to ChromaDB failed: %s", e)

    # ---------------------------------------------------------
    # Backward compatibility for existing pipeline
    # ---------------------------------------------------------
    def find_alternatives(self, query: str, n: int = 5, category: str | None = None):
        results = self.query_similar(query, n_results=n, language=category)
        
        from dataclasses import dataclass
        @dataclass
        class PackageMatch:
            name: str
            description: str
            category: str
            distance: float
            metadata: dict
            
        return [
            PackageMatch(name=name, description=desc, category=category or "", distance=dist, metadata={})
            for name, desc, dist in results
        ]

    def add_packages_batch(self, packages: list[dict[str, Any]]) -> int:
        self.add_packages(packages)
        return len(packages)

    @property
    def count(self) -> int:
        self._ensure_initialized()
        return self._collection.count() if self._collection else 0
