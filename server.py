import os
import json
import re
import time
import uuid
import socket
import hashlib
import tempfile
import asyncio
import logging
import threading
from contextlib import asynccontextmanager
from typing import List, Set, Tuple, AsyncGenerator
from collections import OrderedDict
from urllib.parse import urljoin, urlparse

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
import uvicorn

# =====================================================================
# [ 0. KERNEL & LOGGER SETUP ]
# =====================================================================

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("DriftWatch")

# =====================================================================
# [ 1. CONFIGURATION ]
# =====================================================================

STORE_FILE = "driftwatch_store.json"
MAX_FILE_SIZE = 1048576       
MAX_HTML_SIZE = 5242880       
GLOBAL_DOWNLOAD_LIMIT = 20971520
MAX_HISTORY_LIMIT = 100
MAX_LATEST_LIMIT = 1000
MAX_REDIRECTS = 3
MAX_CONCURRENCY = 20
CHUNK_SIZE = 65536
REGEX_OVERLAP = 512
MAX_ENDPOINTS = 20000 

REGEX_API_BYTES = re.compile(br"(?:\"|'|`)(/(?:api|v[1-9][0-9]*|internal|graphql|admin)[A-Za-z0-9_\-./]+)(?:\"|'|`)")
REGEX_FETCH_BYTES = re.compile(br"(?:fetch|axios(?:\.(?:get|post|put|delete|patch))?)\s*\(\s*['\"`]?(/[^'\"`,\s]+)['\"`]?", re.IGNORECASE)
REGEX_SCRIPT_BYTES = re.compile(br'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)

# =====================================================================
# [ 2. EXCEPTIONS & ATOMIC CONTEXT ]
# =====================================================================

class DownloadLimitExceeded(Exception): pass

class ScanContext:
    def __init__(self):
        self._downloaded = 0
        self._lock = threading.Lock()
        
    def add_bytes(self, size: int):
        with self._lock:
            self._downloaded += size
            if self._downloaded > GLOBAL_DOWNLOAD_LIMIT:
                raise DownloadLimitExceeded("Global download limit exceeded")

# =====================================================================
# [ 3. STATE, RATE LIMIT & WRITE COALESCING ]
# =====================================================================

class DriftWatchState:
    def __init__(self):
        self.memory_lock = asyncio.Lock()
        self.rate_limit_lock = asyncio.Lock()
        
        self.rate_tokens: OrderedDict = OrderedDict()
        self.rate_capacity = 10
        self.rate_window = 60.0
        self._request_counter = 0
        
        self.history: List[dict] = []
        self.latest: OrderedDict = OrderedDict()
        
        self._dirty = asyncio.Event()
        self._is_running = True
        
        # [수정됨] SSRFSafeBackend 제거 및 기본 transport 사용
        limits = httpx.Limits(max_connections=MAX_CONCURRENCY, max_keepalive_connections=MAX_CONCURRENCY)
        transport = httpx.AsyncHTTPTransport(limits=limits, http2=True)
        self.client = httpx.AsyncClient(transport=transport, headers={'User-Agent': 'Mozilla/5.0 DriftWatch/Final'})
        self._load_store()

    def _load_store(self):
        if not os.path.exists(STORE_FILE): return
        try:
            with open(STORE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.history = data.get("history", [])[:MAX_HISTORY_LIMIT]
                self.latest = OrderedDict(list(data.get("latest", {}).items())[-MAX_LATEST_LIMIT:])
        except Exception: pass

    async def enforce_rate_limit(self, client_ip: str):
        now = time.monotonic()
        async with self.rate_limit_lock:
            self._request_counter += 1
            if self._request_counter % 1000 == 0 or len(self.rate_tokens) > 5000:
                stale = [k for k, v in self.rate_tokens.items() if now - v[1] > self.rate_window]
                for k in stale: del self.rate_tokens[k]
                while len(self.rate_tokens) > 5000: self.rate_tokens.popitem(last=False)

            if client_ip in self.rate_tokens:
                self.rate_tokens.move_to_end(client_ip)
                tokens, last_time = self.rate_tokens[client_ip]
            else:
                tokens, last_time = self.rate_capacity, now

            tokens = min(self.rate_capacity, tokens + (now - last_time) * (self.rate_capacity / self.rate_window))
            if tokens >= 1:
                self.rate_tokens[client_ip] = (tokens - 1, now)
            else:
                self.rate_tokens[client_ip] = (tokens, now)
                raise HTTPException(status_code=429, detail="Too Many Requests")

    async def commit_snapshot_memory(self, snapshot: 'SnapshotDTO', current_endpoints: List[str]):
        async with self.memory_lock:
            target_url = snapshot.target_url
            self.latest[target_url] = current_endpoints
            self.latest.move_to_end(target_url)
            if len(self.latest) > MAX_LATEST_LIMIT: self.latest.popitem(last=False)
            self.history.insert(0, snapshot.model_dump())
            if len(self.history) > MAX_HISTORY_LIMIT: self.history.pop()
        self._dirty.set()

    def _write_snapshot_disk_sync(self):
        fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(STORE_FILE)))
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump({"latest": self.latest, "history": self.history}, f, separators=(',', ':'))
            os.replace(temp_path, STORE_FILE)
        except Exception:
            if os.path.exists(temp_path): os.remove(temp_path)

    async def disk_writer_loop(self):
        while self._is_running:
            await self._dirty.wait()
            if not self._is_running: break
            self._dirty.clear()
            await asyncio.sleep(1.0)
            self._dirty.clear()
            await asyncio.to_thread(self._write_snapshot_disk_sync)

    def shutdown_sync(self):
        self._is_running = False
        self._dirty.set()
        self._write_snapshot_disk_sync()

app_state = DriftWatchState()

# =====================================================================
# [ 4. NETWORK ENGINE ]
# =====================================================================

class AsyncNetworkEngine:
    @staticmethod
    def _validate_logical_url(url: str):
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("Invalid logical URL")

    @staticmethod
    @asynccontextmanager
    async def safe_stream(url: str, timeout: float) -> AsyncGenerator[Tuple[httpx.Response, str], None]:
        current_url = url
        resp = None
        try:
            for _ in range(MAX_REDIRECTS):
                AsyncNetworkEngine._validate_logical_url(current_url)
                req = app_state.client.build_request("GET", current_url, timeout=timeout)
                resp = await app_state.client.send(req, stream=True)
                
                if 300 <= resp.status_code < 400 and 'location' in resp.headers:
                    current_url = urljoin(current_url, resp.headers['location'])
                    await resp.aclose()
                    resp = None
                    continue
                if resp.status_code >= 500:
                    resp.raise_for_status()
                yield resp, current_url
                return
            raise ValueError("Too many redirects")
        finally:
            if resp is not None: await resp.aclose()

# =====================================================================
# [ 5. PARSER ENGINE ]
# =====================================================================

class ParserEngine:
    @staticmethod
    async def stream_extract_js_urls(url: str, ctx: ScanContext, timeout: float, max_js: int, same_domain: bool) -> Tuple[List[str], str]:
        js_urls = OrderedDict()
        overlap = b""
        
        async with AsyncNetworkEngine.safe_stream(url, timeout) as (resp, final_url):
            base_domain = urlparse(final_url).netloc
            ctype = resp.headers.get('content-type', '').lower()
            if not any(t in ctype for t in ('text/html', 'application/xhtml+xml')):
                raise ValueError("Invalid HTML Content-Type")

            local_size = 0
            async for chunk in resp.aiter_bytes(chunk_size=CHUNK_SIZE):
                sz = len(chunk)
                local_size += sz
                ctx.add_bytes(sz) 
                if local_size > MAX_HTML_SIZE: break

                buffer = overlap + chunk
                for match in REGEX_SCRIPT_BYTES.finditer(buffer):
                    full_url = urljoin(final_url, match.group(1).decode('utf-8', errors='ignore'))
                    # strict same-domain check
                    if same_domain and not urlparse(full_url).netloc.endswith(base_domain):
                        continue
                        
                    if full_url not in js_urls:
                        js_urls[full_url] = None
                        if len(js_urls) >= max_js:
                            return list(js_urls.keys()), final_url
                overlap = buffer[-REGEX_OVERLAP:] if len(buffer) > REGEX_OVERLAP else buffer

        return list(js_urls.keys()), final_url

    @staticmethod
    async def stream_parse_js(url: str, ctx: ScanContext, timeout: float) -> Set[str]:
        endpoints = set()
        overlap = b""
        try:
            async with AsyncNetworkEngine.safe_stream(url, timeout) as (resp, _):
                ctype = resp.headers.get('content-type', '').lower()
                # loose mime check
                if 'javascript' not in ctype and 'ecmascript' not in ctype:
                    return endpoints

                local_size = 0
                async for chunk in resp.aiter_bytes(chunk_size=CHUNK_SIZE):
                    sz = len(chunk)
                    local_size += sz
                    ctx.add_bytes(sz)
                    if local_size > MAX_FILE_SIZE: break

                    buffer = overlap + chunk
                    for match in REGEX_API_BYTES.finditer(buffer):
                        endpoints.add(match.group(1).decode('utf-8', errors='ignore'))
                    for match in REGEX_FETCH_BYTES.finditer(buffer):
                        endpoints.add(match.group(1).decode('utf-8', errors='ignore'))
                    overlap = buffer[-REGEX_OVERLAP:] if len(buffer) > REGEX_OVERLAP else buffer
        except (httpx.RequestError, httpx.TimeoutException, DownloadLimitExceeded): pass
        except Exception as e: logger.warning(f"Unexpected parse error on {url}: {e}")
        return endpoints

# =====================================================================
# [ 6. CORE LOGIC ]
# =====================================================================

class ScanRequest(BaseModel):
    target_url: str
    same_domain_only: bool = True
    max_js: int = Field(30, ge=1, le=100)
    timeout_ms: int = Field(10000, ge=1000, le=30000)
    concurrency: int = Field(8, ge=1, le=MAX_CONCURRENCY)

class EndpointFinding(BaseModel):
    value: str
    is_new: bool
    is_removed: bool

class SnapshotFindings(BaseModel):
    endpoints: List[EndpointFinding]

class SnapshotDTO(BaseModel):
    snapshot_id: str
    snapshot_hash: str
    created_at: int
    target_url: str
    endpoint_count: int
    findings: SnapshotFindings
    previous_count: int

def generate_incremental_hash(endpoints: List[str]) -> str:
    hasher = hashlib.sha256()
    for ep in sorted(endpoints): 
        hasher.update(ep.encode('utf-8'))
    return hasher.hexdigest()

async def perform_scan(req: ScanRequest) -> Tuple[SnapshotDTO, List[str]]:
    ctx = ScanContext()
    timeout_sec = req.timeout_ms / 1000.0

    js_urls, final_url = await ParserEngine.stream_extract_js_urls(
        req.target_url, ctx, timeout_sec, req.max_js, req.same_domain_only
    )

    semaphore = asyncio.Semaphore(req.concurrency)
    async def bounded_parse(url: str):
        async with semaphore:
            return await ParserEngine.stream_parse_js(url, ctx, timeout_sec)

    tasks = [bounded_parse(url) for url in js_urls]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_endpoints = set()
    for r in results:
        if isinstance(r, set): all_endpoints.update(r)

    current_endpoints = sorted(list(all_endpoints))[:MAX_ENDPOINTS]
    previous_endpoints = app_state.latest.get(req.target_url, [])
    
    prev_set, curr_set = set(previous_endpoints), set(current_endpoints)
    added = curr_set - prev_set
    removed = prev_set - curr_set

    findings_list = [EndpointFinding(value=ep, is_new=(ep in added), is_removed=False) for ep in current_endpoints] + \
                    [EndpointFinding(value=ep, is_new=False, is_removed=True) for ep in removed]

    snapshot = SnapshotDTO(
        snapshot_id=uuid.uuid4().hex[:16],
        snapshot_hash=generate_incremental_hash(current_endpoints),
        created_at=int(time.time()),
        target_url=req.target_url,
        endpoint_count=len(current_endpoints),
        findings=SnapshotFindings(endpoints=findings_list),
        previous_count=len(previous_endpoints)
    )
    return snapshot, current_endpoints

# =====================================================================
# [ 7. API LAYER ]
# =====================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    writer_task = asyncio.create_task(app_state.disk_writer_loop())
    yield
    app_state.shutdown_sync()
    writer_task.cancel()
    try: await writer_task
    except asyncio.CancelledError: pass

app = FastAPI(title="DriftWatch Security API", lifespan=lifespan)
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/api/scan", response_model=SnapshotDTO)
async def api_scan(req: ScanRequest, request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    await app_state.enforce_rate_limit(client_ip)
    
    try:
        snapshot, current_endpoints = await perform_scan(req)
    except DownloadLimitExceeded as e:
        raise HTTPException(status_code=413, detail=str(e))
    except (httpx.TimeoutException, httpx.ConnectTimeout):
        raise HTTPException(status_code=408, detail="Request Timeout")
    except socket.error as e:
        raise HTTPException(status_code=400, detail=str(e)) 
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception("Unhandled scan error")
        raise HTTPException(status_code=500, detail="Internal scan error")
    
    await app_state.commit_snapshot_memory(snapshot, current_endpoints)
    return snapshot

@app.get("/api/snapshots")
async def api_get_snapshots(limit: int = 5):
    async with app_state.memory_lock:
        return {"items": app_state.history[:limit]}

@app.get("/api/snapshots/{snapshot_id}", response_model=SnapshotDTO)
async def api_get_snapshot(snapshot_id: str):
    async with app_state.memory_lock:
        for snap in app_state.history:
            if snap.get("snapshot_id") == snapshot_id:
                return snap
    raise HTTPException(status_code=404, detail="Snapshot not found")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)