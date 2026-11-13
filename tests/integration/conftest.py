"""Fixtures for the integration tests; the harness itself is `_harness.py`."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import anyio
import httpx2
import pytest
import uvicorn
from _harness import Running, World, env, until_ready
from starlette.applications import Starlette

from okta_mcp.app import serve_http
from okta_mcp.config import Config, load_config
from okta_mcp.registry.loader import Registry, load_registry
from okta_mcp.registry.spec import SpecIndex, load_spec


@pytest.fixture(scope="module")
def loaded() -> tuple[SpecIndex, Registry]:
    spec = load_spec()
    return spec, load_registry(spec)


@pytest.fixture(autouse=True)
def load_once(loaded: tuple[SpecIndex, Registry], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("okta_mcp.server.load_spec", lambda: loaded[0])
    monkeypatch.setattr("okta_mcp.server.load_registry", lambda spec: loaded[1])


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return load_config(env(tmp_path))


@pytest.fixture
def world() -> World:
    return World()


@pytest.fixture
def running(monkeypatch: pytest.MonkeyPatch) -> Running:
    """`running(config, world)`: an async context manager that runs `serve_http` with uvicorn
    replaced, and yields the app it would have served."""

    @asynccontextmanager
    async def run(
        config: Config, world: World, *, wait_ready: bool = True
    ) -> AsyncIterator[Starlette]:
        apps: list[Starlette] = []
        started, stop = anyio.Event(), anyio.Event()

        async def serve(self: uvicorn.Server) -> None:
            app = self.config.app
            assert isinstance(app, Starlette)
            async with app.router.lifespan_context(app):
                apps.append(app)
                started.set()
                await stop.wait()

        monkeypatch.setattr(uvicorn.Server, "serve", serve)
        async with anyio.create_task_group() as tg:
            tg.start_soon(serve_http, config, httpx2.MockTransport(world))
            with anyio.fail_after(5):
                await started.wait()
            (app,) = apps
            if wait_ready:
                await until_ready(app)
            try:
                yield app
            finally:
                stop.set()

    return run
