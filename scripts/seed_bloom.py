"""
Seed Bloom Filter — Downloads PyPI/npm package lists.

Fetches the PyPI simple index and npm search API,
saves them as JSON for the bloom filter.
"""

import json
import re
import sys
from pathlib import Path

import httpx
from rich.console import Console

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.core.config import BLOOM_DIR

console = Console()

def fetch_pypi_packages() -> list[str]:
    """Fetch all package names from PyPI simple index."""
    console.print("[cyan]Fetching PyPI package index...[/cyan]")

    with httpx.Client(timeout=60.0, follow_redirects=True) as client:
        response = client.get("https://pypi.org/simple/")
        response.raise_for_status()

    # Parse package names from HTML anchor tags
    packages = re.findall(r'<a[^>]*>([^<]+)</a>', response.text)
    
    # Normalize: lowercase, underscores to hyphens
    normalized = set()
    for pkg in packages:
        normalized.add(pkg.lower().replace("_", "-"))
        
    normalized_list = list(normalized)
    console.print(f"  [green]✓[/green] Found {len(normalized_list):,} PyPI packages")
    return normalized_list

def fetch_npm_packages() -> list[str]:
    """Fetch top npm packages using npm search API."""
    console.print("[cyan]Fetching npm package list...[/cyan]")
    
    packages = set()
    batch_size = 250
    total_wanted = 10000
    
    with httpx.Client(timeout=30.0) as client:
        for offset in range(0, total_wanted, batch_size):
            try:
                # Text query logic isn't strictly necessary but we can just search 'boost-exact:false' or empty
                # registry.npmjs.org/-/v1/search requires a query string, typically ?text=keyword or popularity
                # Using text="a" as a broad query, but sorting by popularity
                url = f"https://registry.npmjs.org/-/v1/search?text=is:public&size={batch_size}&from={offset}&popularity=1.0"
                response = client.get(url)
                
                # If API rate limits or errors, we'll gracefully stop collecting
                if response.status_code != 200:
                    break
                    
                data = response.json()
                objects = data.get("objects", [])
                if not objects:
                    break
                    
                for obj in objects:
                    pkg_name = obj.get("package", {}).get("name")
                    if pkg_name:
                        packages.add(pkg_name.lower())
                        
                console.print(f"  ... fetched {len(packages)} npm packages", end="\r")
            except Exception as e:
                console.print(f"\n  [yellow]⚠[/yellow] NPM fetch interrupted at offset {offset}: {e}")
                break
                
    console.print()
    packages_list = list(packages)
    console.print(f"  [green]✓[/green] Collected {len(packages_list):,} npm packages")
    return packages_list

def main() -> None:
    """Main seed function."""
    console.print("\n[bold]🌱 Seeding Bloom Filter Data[/bold]\n")

    BLOOM_DIR.mkdir(parents=True, exist_ok=True)

    # Fetch PyPI packages
    try:
        pypi_packages = fetch_pypi_packages()
        pypi_path = BLOOM_DIR / "pypi_packages.json"
        with open(pypi_path, "w") as f:
            json.dump(pypi_packages, f)
        console.print(f"  [green]✓[/green] Saved PyPI to {pypi_path}")
    except Exception as e:
        console.print(f"  [red]✗[/red] PyPI fetch failed: {e}")

    # Fetch npm packages
    try:
        npm_packages = fetch_npm_packages()
        npm_path = BLOOM_DIR / "npm_packages.json"
        with open(npm_path, "w") as f:
            json.dump(npm_packages, f)
        console.print(f"  [green]✓[/green] Saved NPM to {npm_path}")
    except Exception as e:
        console.print(f"  [red]✗[/red] npm fetch failed: {e}")

    console.print("\n[green]✓ Bloom filter data seeded successfully![/green]\n")

if __name__ == "__main__":
    main()
