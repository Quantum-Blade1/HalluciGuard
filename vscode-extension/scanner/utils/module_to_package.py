"""
Module-to-Package Name Mapping.

Maps Python module names to their corresponding PyPI package names,
handling common mismatches. Contains ~150 popular mappings.
"""

from __future__ import annotations

MODULE_TO_PACKAGE: dict[str, str] = {
    # Imaging
    "PIL": "Pillow",
    "cv2": "opencv-python",
    "skimage": "scikit-image",
    "imageio": "imageio",
    "matplotlib.pyplot": "matplotlib",
    "pylab": "matplotlib",
    "sns": "seaborn",
    "pytesseract": "pytesseract",
    "graphviz": "graphviz",
    "wand": "Wand",

    # Data / ML
    "sklearn": "scikit-learn",
    "tf": "tensorflow",
    "torch": "torch",
    "pd": "pandas",
    "np": "numpy",
    "scipy": "scipy",
    "statsmodels": "statsmodels",
    "xgboost": "xgboost",
    "lightgbm": "lightgbm",
    "catboost": "catboost",
    "spacy": "spacy",
    "nltk": "nltk",
    "gensim": "gensim",
    "transformers": "transformers",
    "datasets": "datasets",
    "accelerate": "accelerate",
    "diffusers": "diffusers",
    "timm": "timm",

    # YAML / Config / Formats
    "yaml": "PyYAML",
    "dotenv": "python-dotenv",
    "toml": "toml",
    "tomllib": "tomli",
    "xmltodict": "xmltodict",
    "h5py": "h5py",
    "pyarrow": "pyarrow",

    # Parsing / Scraping
    "bs4": "beautifulsoup4",
    "lxml": "lxml",
    "requests": "requests",
    "urllib3": "urllib3",
    "httpx": "httpx",
    "aiohttp": "aiohttp",
    "selenium": "selenium",
    "playwright": "playwright",
    "scrapy": "Scrapy",

    # Date / Time
    "dateutil": "python-dateutil",
    "arrow": "arrow",
    "pendulum": "pendulum",
    "pytz": "pytz",
    "freezegun": "freezegun",

    # Serialization
    "msgpack": "msgpack",
    "ujson": "ujson",
    "orjson": "orjson",
    "simplejson": "simplejson",
    "marshmallow": "marshmallow",
    "pydantic": "pydantic",
    "cerberus": "Cerberus",
    "voluptuous": "voluptuous",

    # Database / ORM
    "psycopg2": "psycopg2-binary",
    "MySQLdb": "mysqlclient",
    "pymysql": "PyMySQL",
    "sqlalchemy": "SQLAlchemy",
    "alembic": "alembic",
    "pymongo": "pymongo",
    "redis": "redis",
    "sqlite3": "pysqlite3",  # Builtin usually, but if overridden
    "peewee": "peewee",
    "pony": "pony",
    "motor": "motor",
    "cassandra": "cassandra-driver",

    # Web / HTTP / ASGI / WSGI
    "flask": "Flask",
    "werkzeug": "Werkzeug",
    "jinja2": "Jinja2",
    "markupsafe": "MarkupSafe",
    "starlette": "starlette",
    "fastapi": "fastapi",
    "uvicorn": "uvicorn",
    "django": "Django",
    "tornado": "tornado",
    "gunicorn": "gunicorn",
    "channels": "channels",
    "socketio": "python-socketio",

    # Crypto / Security
    "Crypto": "pycryptodome",
    "Cryptodome": "pycryptodome",
    "nacl": "PyNaCl",
    "jwt": "PyJWT",
    "jose": "python-jose",
    "passlib": "passlib",
    "bcrypt": "bcrypt",
    "cryptography": "cryptography",
    "OpenSSL": "pyOpenSSL",

    # Testing
    "pytest": "pytest",
    "_pytest": "pytest",
    "mock": "mock",
    "responses": "responses",
    "factory": "factory_boy",
    "faker": "Faker",
    "tox": "tox",
    "nox": "nox",
    "coverage": "coverage",
    "vcr": "vcrpy",

    # Cloud / AWS / GCP / Azure
    "google.cloud": "google-cloud-core",
    "google.auth": "google-auth",
    "boto3": "boto3",
    "botocore": "botocore",
    "sagemaker": "sagemaker",
    "azure.storage.blob": "azure-storage-blob",
    "azure.identity": "azure-identity",
    "stripe": "stripe",
    "twilio": "twilio",
    "sendgrid": "sendgrid",
    "telebot": "pyTelegramBotAPI",

    # Misc / Utils / CLI
    "attr": "attrs",
    "attrs": "attrs",
    "gi": "PyGObject",
    "wx": "wxPython",
    "serial": "pyserial",
    "usb": "pyusb",
    "magic": "python-magic",
    "docx": "python-docx",
    "pptx": "python-pptx",
    "openpyxl": "openpyxl",
    "fitz": "PyMuPDF",
    "colorama": "colorama",
    "tqdm": "tqdm",
    "rich": "rich",
    "click": "click",
    "typer": "typer",
    "argcomplete": "argcomplete",
    "docopt": "docopt",
    "fire": "fire",
    "prompt_toolkit": "prompt_toolkit",
    "pygments": "Pygments",
    "tenacity": "tenacity",
    "retrying": "retrying",
    "schedule": "schedule",
    "apscheduler": "APScheduler",
    "celery": "celery",
    "kombu": "kombu",
    "pika": "pika",
    "kafka": "kafka-python",
    "confluent_kafka": "confluent-kafka",
    "fabric": "fabric",
    "invoke": "invoke",
    "paramiko": "paramiko",
    "ansible": "ansible",
    "docker": "docker",
    "kubernetes": "kubernetes",
    "jsonschema": "jsonschema",
    "ruamel.yaml": "ruamel.yaml",
    "packaging": "packaging",
    "pkg_resources": "setuptools",
    "wheel": "wheel",
    "twine": "twine",
    "build": "build",
    "flake8": "flake8",
    "black": "black",
    "isort": "isort",
    "mypy": "mypy",
    "pylint": "pylint",
    "bandit": "bandit",
    "loguru": "loguru",
    "structlog": "structlog",
    "sentry_sdk": "sentry-sdk",
    "datadog": "datadog",
    "prometheus_client": "prometheus-client",
    "opentelemetry": "opentelemetry-api",
}

def module_to_package(module_name: str) -> str:
    """Map a Python module name to its PyPI package name.

    Handles dotted module paths by checking the top-level module first.
    """
    # Direct match
    if module_name in MODULE_TO_PACKAGE:
        return MODULE_TO_PACKAGE[module_name]

    # Try top-level module for dotted paths
    parts = module_name.split(".")
    for i in range(len(parts), 0, -1):
        prefix = ".".join(parts[:i])
        if prefix in MODULE_TO_PACKAGE:
            return MODULE_TO_PACKAGE[prefix]

    # No mapping found — assume module name == package name
    return parts[0]


def is_relative_import(module_name: str) -> bool:
    """Check if a module name looks like a relative/local import."""
    if module_name.startswith("."):
        return True
    if module_name.startswith("_") and "." not in module_name:
        return True
    return False
