"""
Seed ChromaDB with Top PyPI Packages.

Fetches descriptions for hard-coded popular PyPI packages
and inserts them into the ChromaDB vector store.
"""

import asyncio
import sys
from pathlib import Path

import httpx
from rich.console import Console

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.data.chroma_manager import ChromaManager

console = Console()

# Hardcoded top 200 list for speed during hackathon
TOP_PACKAGES = [
    "requests", "flask", "django", "numpy", "pandas", "scipy", "scikit-learn",
    "matplotlib", "seaborn", "tensorflow", "torch", "keras", "pillow",
    "opencv-python", "beautifulsoup4", "lxml", "sqlalchemy", "pymongo",
    "redis", "celery", "pytest", "mock", "coverage", "tox", "pyyaml",
    "python-dateutil", "pytz", "six", "cryptography", "paramiko",
    "fabric", "ansible", "boto3", "botocore", "google-api-python-client",
    "jinja2", "werkzeug", "click", "typer", "fastapi", "uvicorn", "starlette",
    "pydantic", "alembic", "marshmallow", "gunicorn", "tornado", "twisted",
    "asyncio", "aiohttp", "httpx", "urllib3", "idna", "certifi", "chardet",
    "colorama", "rich", "tqdm", "prompt_toolkit", "pygments", "docopt",
    "argparse", "flake8", "black", "isort", "mypy", "pylint", "bandit",
    "sphinx", "mkdocs", "jupyter", "ipython", "notebook", "jupyterlab",
    "virtualenv", "pipenv", "poetry", "setuptools", "wheel", "twine",
    "build", "packaging", "jsonschema", "simplejson", "ujson", "orjson",
    "msgpack", "protobuf", "grpcio", "pika", "kafka-python", "confluent-kafka",
    "psycopg2-binary", "mysqlclient", "pysqlite3", "peewee", "pony",
    "passlib", "bcrypt", "pyjwt", "python-jose", "oauthlib", "requests-oauthlib",
    "beautifulsoup4", "scrapy", "selenium", "playwright", "pyppeteer",
    "pyarrow", "fastparquet", "h5py", "zarr", "dask", "ray", "numba",
    "cython", "cffi", "pypy", "joblib", "timm", "transformers", "datasets",
    "accelerate", "diffusers", "tokenizers", "sentencepiece", "spacy",
    "nltk", "gensim", "textblob", "pattern", "langchain", "llama-index",
    "chromadb", "pinecone-client", "weaviate-client", "qdrant-client",
    "milvus", "faiss-cpu", "faiss-gpu", "xgboost", "lightgbm", "catboost",
    "statsmodels", "prophet", "pmdarima", "sktime", "tsfresh", "networkx",
    "graphviz", "python-igraph", "dash", "streamlit", "gradio", "bokeh",
    "plotly", "altair", "pyecharts", "folium", "geopandas", "shapely",
    "fiona", "rasterio", "pyproj", "openpyxl", "xlrd", "xlwt", "xlsxwriter",
    "python-docx", "python-pptx", "pypdf2", "pdfminer.six", "fitz", "pymupdf",
    "wand", "imageio", "scikit-image", "pydicom", "nibabel", "librosa",
    "soundfile", "pydub", "pygame", "pyglet", "arcade", "panda3d", "kivy",
    "pyqt5", "pyqt6", "pyside2", "pyside6", "wxpython", "tkinter", "turtle"
]

async def fetch_package_description(client: httpx.AsyncClient, pkg: str) -> dict | None:
    url = f"https://pypi.org/pypi/{pkg}/json"
    try:
        response = await client.get(url)
        if response.status_code == 200:
            data = response.json()
            summary = data.get("info", {}).get("summary", "")
            return {"name": pkg, "description": summary, "language": "python"}
    except Exception:
        pass
    return None

async def seed_chroma() -> None:
    console.print("\n[bold]📦 Seeding ChromaDB Safe Packages...[/bold]\n")
    
    manager = ChromaManager()
    
    # We will only pull packages that aren't already in there
    # But for a quick hackathon script, just upsert everything
    packages_to_add = []
    
    async with httpx.AsyncClient(http2=True, timeout=10.0) as client:
        tasks = [fetch_package_description(client, pkg) for pkg in list(set(TOP_PACKAGES))]
        results = await asyncio.gather(*tasks)
        
    for res in results:
        if res and res["description"]:
            packages_to_add.append(res)
            
    if packages_to_add:
        manager.add_packages(packages_to_add)
        console.print(f"  [green]✓[/green] Added {len(packages_to_add)} packages to ChromaDB.")
    else:
        console.print("  [yellow]⚠[/yellow] No packages fetched.")
        
    console.print(f"  [cyan]ℹ[/cyan] Total documents in ChromaDB: {manager.count}")

if __name__ == "__main__":
    asyncio.run(seed_chroma())
