"""
Async Registry Client for PyPI and npm.

Performs HTTP lookups to verify package existence and fetch metadata.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

@dataclass
class RegistryResult:
    """Metadata retrieved from a package registry."""
    exists: bool
    first_upload: str = ""
    download_count: int = 0
    description: str = ""


class RegistryClient:
    """Async client for PyPI and npm package registries."""

    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                http2=True,
                timeout=httpx.Timeout(3.0, connect=2.0),
                follow_redirects=True,
                headers={"Accept": "application/json"},
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def check_pypi(self, package_name: str) -> RegistryResult:
        """Check if a package exists on PyPI."""
        url = f"https://pypi.org/pypi/{package_name}/json"
        client = await self._get_client()

        try:
            response = await client.get(url)
            if response.status_code == 404:
                return RegistryResult(exists=False)

            if response.status_code == 200:
                data = response.json()
                info = data.get("info", {})
                
                releases = data.get("releases", {})
                first_upload = ""
                if releases:
                    first_version = next(iter(releases.values()), [])
                    if first_version and isinstance(first_version, list):
                        first_upload = first_version[0].get("upload_time", "")

                return RegistryResult(
                    exists=True,
                    first_upload=first_upload,
                    download_count=0,
                    description=info.get("summary", ""),
                )
        except Exception as e:
            logger.warning("PyPI lookup failed for %s: %s", package_name, e)

        return RegistryResult(exists=False)

    async def check_npm(self, package_name: str) -> RegistryResult:
        """Check if a package exists on npm."""
        url = f"https://registry.npmjs.org/{package_name}"
        client = await self._get_client()

        try:
            response = await client.get(url)
            if response.status_code == 404:
                return RegistryResult(exists=False)

            if response.status_code == 200:
                data = response.json()
                time_info = data.get("time", {})
                first_upload = time_info.get("created", "")

                return RegistryResult(
                    exists=True,
                    first_upload=first_upload,
                    download_count=0,  # npm doesn't expose this in main json
                    description=data.get("description", ""),
                )
        except Exception as e:
            logger.warning("npm lookup failed for %s: %s", package_name, e)

        return RegistryResult(exists=False)

    async def check_package(self, package_name: str, ecosystem: str = "pypi") -> RegistryResult:
        if ecosystem == "npm":
            return await self.check_npm(package_name)
        return await self.check_pypi(package_name)

    async def check_packages(self, packages: list[tuple[str, str]]) -> list[RegistryResult]:
        """Run all lookups in parallel via asyncio.gather."""
        tasks = [self.check_package(name, eco) for name, eco in packages]
        return await asyncio.gather(*tasks)
