# okta-mcp container image (design §11.2). Build: docker build -t okta-mcp .
# Both stages use the same base (BASE_IMAGE, below): the venv's interpreter is a symlink into it.
# Dependabot (docker ecosystem) bumps the pinned digests; it reads FROM lines only, hence the
# uv stage. Keep uv's version equal to setup-uv's in .github/workflows/ci.yml.
# HEALTHCHECK --start-interval needs Docker Engine 25 or later.
#
# BASE_IMAGE replaces the Python base of both stages (they must match: see above), for example
# an internal mirror or a hardened base:
#   docker build --build-arg BASE_IMAGE=registry.example.com/python:3.12-slim@sha256:<digest> .
# It must be pinned by digest; the build refuses a tag. The base must be Debian or Ubuntu
# (apt-get, groupadd, useradd) with Python >= 3.12 on PATH. Dependabot does not track it. Run
# tests/container against the result (OKTA_MCP_IMAGE=<tag>): a base that keeps pip
# outside /usr/local, for one, fails test_no_pip. The default is the pinned stage below.
ARG BASE_IMAGE=python-base

FROM ghcr.io/astral-sh/uv:0.12.24@sha256:3af4716e991d6956a41e573eab705d0ee08500cd829ed30293eb8472f372c65a AS uv

FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS python-base

FROM ${BASE_IMAGE} AS build
ARG BASE_IMAGE
# Fail closed on a tag: the same tag can name a different image in each stage, or tomorrow.
# The `case` refuses whitespace first, since grep -x matches line by line.
RUN case "$BASE_IMAGE" in *[[:space:]]*) false ;; esac \
    && printf '%s\n' "$BASE_IMAGE" | grep -Eqx 'python-base|[^[:space:]]+@sha256:[0-9a-f]{64}' \
    || { echo "BASE_IMAGE must be pinned by digest (image@sha256:<64 hex>)" >&2; exit 1; }
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
# Dependencies first, so a source change doesn't refetch them.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY LICENSE README.md ./
COPY src/ src/
# Non-editable: the package (with its data files) is installed into the venv, so the runtime
# stage needs no source tree. No group/other write bits anywhere in the venv (uv leaves its
# `.lock` at 0666): only root may change the code the server imports.
RUN uv sync --frozen --no-dev --no-editable && chmod -R go-w /app/.venv

FROM ${BASE_IMAGE}
# Distribution security fixes released since the base digest was built. For the default base,
# the pinned digest moves only when Dependabot bumps it (after a cooldown), and CI's image scan
# fails on fixed HIGH/CRITICAL; with a custom BASE_IMAGE, its updates and scanning are yours.
# The server never installs anything: drop pip (and ensurepip's bundled copy), and the
# setuid/setgid bits (su, mount, passwd, ...) a non-root process could use to change identity.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /usr/local/lib/python3.*/site-packages/pip /usr/local/lib/python3.*/site-packages/pip-* \
        /usr/local/lib/python3.*/ensurepip /usr/local/bin/pip /usr/local/bin/pip3* \
    && find / -xdev -perm /6000 -type f -exec chmod a-s {} + \
    && groupadd --system --gid 10001 mcp \
    && useradd --system --uid 10001 --gid 10001 --no-create-home --no-log-init \
        --home-dir /nonexistent --shell /usr/sbin/nologin mcp
WORKDIR /app
# Root-owned and not writable by the server; it runs on a read-only root filesystem.
COPY --from=build /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8080 \
    MCP_ENV=production
USER 10001:10001
EXPOSE 8080
# /healthz is unauthenticated and data-free (§11.4). Follows MCP_HOST/MCP_PORT overrides,
# stripped as config does (a wildcard bind is probed on loopback), and ignores HTTP(S)_PROXY,
# which an operator may set for the Okta calls: a proxy can't reach the container's loopback.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --start-interval=2s --retries=3 \
    CMD ["python", "-c", "import os,sys,urllib.request as u; h=os.environ.get('MCP_HOST','').strip() or '0.0.0.0'; h={'0.0.0.0':'127.0.0.1','::':'::1'}.get(h,h); h='[%s]'%h if ':' in h else h; r=u.build_opener(u.ProxyHandler({})).open('http://%s:%s/healthz'%(h,os.environ.get('MCP_PORT','').strip() or '8080'),timeout=2); sys.exit(0 if r.status==200 else 1)"]
ENTRYPOINT ["okta-mcp"]
