"""Entrypoint for ``python -m panel``; managed TLS renewal and debug reload."""

from __future__ import annotations

from uvicorn.supervisors import ChangeReload

from .config import get_settings
from .tls_reload import TLSConfig, TLSServer


def main() -> None:
    settings = get_settings()
    ssl_kwargs = {}
    if settings.tls_cert or settings.tls_key:
        if not settings.tls_cert or not settings.tls_key:
            raise ValueError("both TLS certificate and private-key paths are required")
        ssl_kwargs = {
            "ssl_certfile": str(settings.tls_cert),
            "ssl_keyfile": str(settings.tls_key),
        }

    config = TLSConfig(
        "panel.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        startup_retry_interval=max(1, getattr(settings, "tls_reload_interval", 60)),
        **ssl_kwargs,
    )
    server = TLSServer(config)
    if config.should_reload:
        # Match uvicorn.run's dispatch, leaving TLS initialization to each
        # worker's Config.load() rather than constructing SSLContexts here.
        sock = config.bind_socket()
        try:
            ChangeReload(config, target=server.run, sockets=[sock]).run()
        finally:
            sock.close()
    else:
        server.run()


if __name__ == "__main__":
    main()
