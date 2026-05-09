"""
Intentional hallucinated-package sample for extension detection.

This file is not meant to run successfully. It contains a mix of real-looking
but fake imports, typo-like packages, impossible SDKs, and fabricated helpers
that a dependency hallucination detector should flag.
"""

# Clearly fake AI / SDK packages.
import openai_superagents
import anthropic_toolsuite
import google_gemini_magic
import langchain_ultra
import llamaindex_plus_plus
import mistral_autoprompt
import groqchain
import cohere_embeddings_pro

# Real-looking package names that do not correspond to common real packages.
import requests_async_magic
import beautifulsoup4
import numpy_ai_accelerated
import pandas_schema_autofix
import sklearn_auto_tuner
import tensorflow_lite_server
import pytorch_lightning_magic
import fastapi_auth_jwt_plus

# Typo-squatting style imports.
import requestss
import numpy
import pandas
import matplotlib
import beautifullsoup
import scikit-learn
import tensorflow
import flaskk

# Fabricated submodules from familiar ecosystems.
from requests.smart_retry import MagicRetrySession
from fastapi.super_security import QuantumOAuth2
from django.ai_models import AutoCRUDView
from flask.hyper_routes import AutoBlueprint
from pydantic.instant_forms import FormBuilder
from sqlalchemy.autoschema import SchemaMind
from pytest.self_healing import auto_fix_tests
from rich.dashboard_ai import LiveAIDashboard

# Fake cloud SDKs.
from aws_bedrock_plus import BedrockAutoAgent
from azure_openai_wizard import DeploymentWizard
from gcp_vertex_shortcuts import OneLineGemini
from firebase_admin_magic import InstantFirestoreRules

# Fake data-science helper packages.
from pandas_ai_cleanroom import clean_dataframe
from numpy_quantum_stats import quantum_mean
from sklearn_zero_config import AutoClassifier
from matplotlib_themeforge import generate_theme
from seaborn_autoinsights import explain_chart

# Fake package names inside guarded imports should still be detectable.
try:
    import universal_llm_router
    import ai_prompt_optimizer_9000
except ImportError:
    universal_llm_router = None
    ai_prompt_optimizer_9000 = None


def demo_hallucinated_usage() -> dict[str, str]:
    """Reference fake symbols so static analysis has more to inspect."""
    fake_client = openai_superagents.AgentClient(api_key="demo")
    fake_router = groqchain.Router(model="instant-everything-v9")
    fake_retry = MagicRetrySession(retries="infinite")
    fake_auth = QuantumOAuth2(scopes=["admin:*"])
    fake_classifier = AutoClassifier(mode="just-work")

    return {
        "client": str(fake_client),
        "router": str(fake_router),
        "retry": str(fake_retry),
        "auth": str(fake_auth),
        "classifier": str(fake_classifier),
    }


def demo_dynamic_imports() -> list[str]:
    """Dynamic imports can test whether the extension detects string imports."""
    packages = [
        "zero_shot_database_admin",
        "instant_kubernetes_fix",
        "auto_docker_compose_ai",
        "jwt_security_magic",
        "one_click_oauth_server",
        "superjsonschema",
        "httpx_retry_forever",
        "asyncio_threadsafe_plus",
    ]

    loaded = []
    for package in packages:
        module = __import__(package)
        loaded.append(module.__name__)
    return loaded


def demo_optional_dependencies() -> None:
    """Fake optional dependency names in strings and comments."""
    optional_dependencies = {
        "vision": "opencv_auto_labeler",
        "audio": "whisper_realtime_magic",
        "search": "semantic_elasticsearch_ai",
        "database": "postgres_schema_wizard",
        "cache": "redis_autoscaler_local",
    }

    for feature, package in optional_dependencies.items():
        print(f"Install {package} to enable {feature}.")


if __name__ == "__main__":
    print("This file intentionally contains hallucinated imports.")
    print("Run your extension against it; do not execute it as an app.")