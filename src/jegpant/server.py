"""Uvicorn entrypoint for the private single-owner JEGPANT API.

Before running, configure the owner public key, instance UUID, storage path, and
explicit local-key mode. Production deployments should replace the local-file
provider in service_factory with an external KMS/HSM-backed provider.
"""

from .service_factory import build_app


app = build_app()
