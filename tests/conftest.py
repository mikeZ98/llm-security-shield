"""Shared fixtures. The suite is hermetic: pytest-socket blocks every non-Unix socket."""

import os
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.testclient import TestClient
from presidio_analyzer import AnalyzerEngine
from pydantic import SecretStr

from llm_security_shield.api import ApiSettings, create_app
from llm_security_shield.core import HeuristicSanitizer, ShieldSettings, TokenVault
from llm_security_shield.guardrails import GuardrailPipeline
from llm_security_shield.schemas import PolicyAction, ToolPolicy, ToolRule
from llm_security_shield.tools import PresidioAnonymizer, ToolPolicyGuard, build_analyzer
from tests.support import API_KEY, PII_TEXT, FakeClock


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Settings read SHIELD_* variables; never let the developer's shell leak in."""
    for key in list(os.environ):
        if key.startswith("SHIELD_"):
            monkeypatch.delenv(key)


@pytest.fixture
def settings() -> ShieldSettings:
    return ShieldSettings()


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def vault(clock: FakeClock) -> TokenVault:
    return TokenVault(60, max_entries=100, clock=clock)


@pytest.fixture(scope="session")
def sanitizer() -> HeuristicSanitizer:
    return HeuristicSanitizer()


@pytest.fixture(scope="session")
def analyzer() -> AnalyzerEngine:
    """Loaded once (~1s); proves the spaCy model and suffix list load offline."""
    return build_analyzer()


@pytest.fixture
def anonymizer(vault: TokenVault, analyzer: AnalyzerEngine) -> PresidioAnonymizer:
    return PresidioAnonymizer(vault, analyzer=analyzer)


@pytest.fixture
def sandbox(tmp_path: Path) -> Path:
    """A sandbox root with a file, a subdirectory and a symlink pointing outside."""
    root = tmp_path.resolve() / "sandbox"
    (root / "data").mkdir(parents=True)
    (root / "data" / "ok.txt").write_text("ok")
    (root / "escape").symlink_to(tmp_path.resolve().parent)
    return root


@pytest.fixture
def tool_policy() -> ToolPolicy:
    return ToolPolicy(
        rules=(
            ToolRule(
                name="read_file", action=PolicyAction.ALLOW, allowed_arguments=frozenset({"path"})
            ),
            ToolRule(name="run", action=PolicyAction.REQUIRE_APPROVAL, max_calls_per_request=2),
            ToolRule(name="rm", action=PolicyAction.DENY),
            ToolRule(name="search", action=PolicyAction.ALLOW, max_calls_per_request=1),
        )
    )


@pytest.fixture
def policy_guard(tool_policy: ToolPolicy, sandbox: Path) -> ToolPolicyGuard:
    return ToolPolicyGuard(tool_policy, sandbox_roots=[sandbox])


@pytest.fixture(scope="session")
def pipeline() -> GuardrailPipeline:
    return GuardrailPipeline.default()


def _add_demo_routes(app: FastAPI) -> None:
    """Endpoints imitating an LLM backend, used to exercise the middleware."""

    @app.post("/v1/chat")
    async def chat(request: Request) -> dict[str, Any]:
        body = await request.body()
        return {"id": "c1", "reply": PII_TEXT, "received": len(body), "n": 5}

    @app.get("/v1/search")
    async def search(q: str = "") -> dict[str, int]:
        return {"q_len": len(q)}

    @app.get("/sse")
    async def sse() -> StreamingResponse:
        async def events() -> AsyncIterator[str]:
            yield 'event: delta\ndata: {"content": "Hello John Smith,"}\n\n'
            yield 'data: {"content": "mail me at jo'
            yield 'hn.smith@example.com"}\r\n\r\n'
            yield ": keepalive comment\n\n"
            yield "data: plain text from Berlin\n\n"
            yield "data: [DONE]\n\n"

        return StreamingResponse(events(), media_type="text/event-stream")

    @app.get("/ndjson")
    async def ndjson() -> StreamingResponse:
        async def lines() -> AsyncIterator[str]:
            yield '{"msg": "John Smith"}\n{"msg": "ok"'
            yield '}\nnot json but John Smith\n{"msg": "john.smith@example.com"}'

        return StreamingResponse(lines(), media_type="application/x-ndjson")

    @app.get("/textstream")
    async def textstream() -> StreamingResponse:
        async def chunks() -> AsyncIterator[str]:
            yield "line one mentions John "
            yield "Smith\nline two is fine\n"
            yield "tail 192.168.10.5"

        return StreamingResponse(chunks(), media_type="text/plain")

    @app.get("/json-stream")
    async def json_stream() -> StreamingResponse:
        async def parts() -> AsyncIterator[str]:
            yield '{"reply": "'
            yield 'John Smith"}'

        return StreamingResponse(parts(), media_type="application/json")

    @app.get("/long-line")
    async def long_line() -> StreamingResponse:
        async def parts() -> AsyncIterator[str]:
            yield "John Smith " + "word " * 600

        return StreamingResponse(parts(), media_type="text/plain")

    @app.get("/plain")
    async def plain() -> PlainTextResponse:
        return PlainTextResponse(PII_TEXT)

    @app.get("/latin1")
    async def latin1() -> Response:
        body = ("total " + chr(0xA3) + "5 paid by John Smith").encode("latin-1")
        return Response(body, media_type="text/plain; charset=latin-1")

    @app.get("/gz")
    async def gz() -> JSONResponse:
        return JSONResponse({"a": 1}, headers={"content-encoding": "gzip"})

    @app.get("/binary")
    async def binary() -> Response:
        return Response(b"\x00\x01John Smith", media_type="application/octet-stream")

    @app.get("/big")
    async def big() -> PlainTextResponse:
        return PlainTextResponse("x" * 5_000_000)

    @app.get("/empty-json")
    async def empty_json() -> Response:
        return Response(b"", media_type="application/json")

    @app.get("/bad-json")
    async def bad_json() -> Response:
        return Response(b"{not json", media_type="application/json")

    @app.get("/bad-charset")
    async def bad_charset() -> Response:
        return Response(b"hello", media_type="text/plain; charset=no-such-codec")

    @app.get("/no-content")
    async def no_content() -> Response:
        return Response(status_code=204)

    @app.get("/bad-sse")
    async def bad_sse() -> StreamingResponse:
        async def events() -> AsyncIterator[bytes]:
            yield b"data: \xff\xfe broken utf-8\n\n"

        return StreamingResponse(events(), media_type="text/event-stream")

    @app.get("/boom")
    async def boom() -> None:
        raise RuntimeError("kaboom-internal-detail")


AppFactory = Callable[..., FastAPI]


@pytest.fixture
def app_factory(analyzer: AnalyzerEngine, tool_policy: ToolPolicy) -> AppFactory:
    """Build the shield app plus demo routes; keyword args override ``ApiSettings``."""

    def build(
        *, api_key: str | None = None, settings: ShieldSettings | None = None, **api: Any
    ) -> FastAPI:
        app = create_app(
            settings or ShieldSettings(max_input_chars=5_000),
            ApiSettings(
                api_key=SecretStr(api_key) if api_key else None,
                max_request_bytes=api.pop("max_request_bytes", 20_000),
                **api,
            ),
            tool_policy=tool_policy,
            analyzer=analyzer,
        )
        _add_demo_routes(app)
        return app

    return build


@pytest.fixture
def client(app_factory: AppFactory) -> Iterator[TestClient]:
    with TestClient(app_factory()) as test_client:
        yield test_client


@pytest.fixture
def keyed_client(app_factory: AppFactory) -> Iterator[TestClient]:
    with TestClient(app_factory(api_key=API_KEY)) as test_client:
        yield test_client


@pytest.fixture
async def async_client(app_factory: AppFactory) -> AsyncIterator[httpx.AsyncClient]:
    app = app_factory()
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://shield.test"
        ) as async_test_client,
    ):
        yield async_test_client
