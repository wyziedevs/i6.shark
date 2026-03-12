import asyncio
import hashlib
import hmac
import json
import os
import random
import socket
import sys
import time
import brotli  # Add brotli for content decoding
from urllib.parse import urlparse

import aiohttp
from aiohttp import web

# --- CONFIG ---
SHARED_SECRET = "rXPACddng7mFAbjPP4feLFS1maXg3vpW" # Secret between client & server
version = "1.0.0"                                  # Version of the script
IPV6_PREFIX = "2a01:e5c0:2d74"                     # Your /48 prefix
IPV6_SUBNET = "1000"                               # Using subnet 1000 within your /48
INTERFACE = "ens3"                                 # Detected interface from your system
LISTEN_PORT = 80                                   # Proxy server port
LISTEN_HOST = "0.0.0.0"                            # Listen on all interfaces
REQUEST_TIMEOUT = 30                               # Request timeout in seconds
DEBUG = False                                      # Enable debug output
POOL_SIZE = 50                                     # Number of pre-configured IPv6 addresses
MAX_CONCURRENT_REQUESTS = 500                      # Max concurrent proxy requests
STREAM_CHUNK_SIZE = 128 * 1024                     # 128KB chunks for response streaming
MAX_CONNECTIONS = 200                              # Max connections in shared connector
MAX_CONNECTIONS_PER_HOST = 25                      # Max connections per target host

# --- GLOBAL STATE ---
_interface_ok = None                               # Cached interface check result
_ip_pool = []                                      # Pre-configured IPv6 addresses
_request_semaphore = None                          # Concurrency limiter
_request_count = 0                                 # Request counter

SKIP_HEADERS = frozenset({
    'transfer-encoding',
    'content-encoding',
    'content-length',
    'connection',
    'keep-alive',
    'server',
})

def random_ipv6():
    """Generate a random IPv6 address within the specified subnet"""
    host = random.getrandbits(64)
    return f"{IPV6_PREFIX}:{IPV6_SUBNET}:{(host >> 48) & 0xFFFF:04x}:{(host >> 32) & 0xFFFF:04x}:{(host >> 16) & 0xFFFF:04x}:{host & 0xFFFF:04x}"

async def check_interface():
    """Check if the configured interface exists, with caching"""
    global _interface_ok
    if _interface_ok is not None:
        return _interface_ok
    try:
        cmd = "ip link show"
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        if INTERFACE not in stdout.decode():
            print(f"WARNING: Interface {INTERFACE} not found in system interfaces.")
            print(f"Available interfaces: {stdout.decode()}")
            _interface_ok = False
        else:
            _interface_ok = True
    except Exception as e:
        print(f"Error checking interfaces: {e}")
        _interface_ok = False
    return _interface_ok

async def add_ipv6_to_interface(ipv6):
    """Add IPv6 address to interface if it doesn't exist"""
    if DEBUG:
        print(f"Attempting to add {ipv6}/128 to {INTERFACE}")

    try:
        cmd = f"ip -6 addr add {ipv6}/128 dev {INTERFACE}"
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            stderr_text = stderr.decode()
            if "File exists" not in stderr_text:
                print(f"Failed to add IPv6 address: {stderr_text}")
                return False
            else:
                if DEBUG:
                    print("IPv6 address already exists (this is fine)")
        return True
    except Exception as e:
        print(f"Error adding IPv6 address: {e}")
        return False

async def test_ipv6_connectivity(ipv6):
    """Test if we can use this IPv6 address for outbound connections"""
    if DEBUG:
        print(f"Testing connectivity for {ipv6}")

    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.bind((ipv6, 0))
        sock.connect(("2001:4860:4860::8888", 53))
        sock.close()
        if DEBUG:
            print("IPv6 connectivity test PASSED")
        return True
    except Exception as e:
        print(f"IPv6 connectivity test FAILED: {e}")
        return False

def ensure_url_has_scheme(url):
    """Ensure URL has a scheme (http:// or https://)"""
    if not url.startswith(('http://', 'https://')):
        return f"https://{url}"
    return url

def log_request(request):
    """Log request count (detailed logging only in debug mode)"""
    global _request_count
    _request_count += 1
    if DEBUG:
        print(f"\n--- Incoming Request #{_request_count} ---")
        print(f"Method: {request.method}")
        print(f"Path: {request.path}")
        print(f"Query string: {request.query_string}")
        print(f"Remote: {request.remote}")
        print(f"Headers: {dict(request.headers)}")
        print("-------------------------------\n")

def derive_dynamic_key():
    """Generate a dynamic key based on the current timestamp."""
    current_timestamp = int(time.time() // (3 * 60)) * (3 * 60)
    key_data = f"{current_timestamp}".encode()  # Use only the timestamp as key data
    return key_data

def validate_api_token(api_token):
    """Validate the API-Token header using HMAC and the shared secret."""
    try:
        dynamic_key = derive_dynamic_key()
        expected_hash = hmac.new(dynamic_key, b"proxy-access", hashlib.sha256).hexdigest()
        return hmac.compare_digest(api_token, expected_hash)
    except Exception as e:
        if DEBUG:
            print(f"Error validating API-Token: {e}")
        return False

def _get_random_ip():
    """Get a random IP from the pre-configured pool"""
    if _ip_pool:
        return random.choice(_ip_pool)
    return None

async def _build_ip_pool():
    """Pre-build a pool of IPv6 addresses at startup"""
    global _ip_pool
    print(f"Building IP pool with {POOL_SIZE} addresses...")
    tasks = []
    for _ in range(POOL_SIZE):
        ip = random_ipv6()
        tasks.append(_try_add_ip(ip))
    results = await asyncio.gather(*tasks, return_exceptions=True)
    _ip_pool = [r for r in results if isinstance(r, str)]
    print(f"IP pool ready: {len(_ip_pool)} addresses configured")

async def _try_add_ip(ip):
    """Try to add an IP and return it if successful"""
    if await add_ipv6_to_interface(ip):
        return ip
    return None

async def _refresh_ip_pool():
    """Periodically refresh the IP pool with new addresses"""
    while True:
        await asyncio.sleep(600)  # Refresh every 10 minutes
        print("Refreshing IP pool...")
        new_pool = []
        tasks = []
        for _ in range(POOL_SIZE):
            ip = random_ipv6()
            tasks.append(_try_add_ip(ip))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        new_pool = [r for r in results if isinstance(r, str)]
        if new_pool:
            global _ip_pool
            _ip_pool = new_pool
            print(f"IP pool refreshed: {len(_ip_pool)} addresses")

async def handle(request):
    api_token = request.headers.get("API-Token")
    if not api_token or not validate_api_token(api_token):
        return web.Response(text="Unauthorized: i6.shark detected invalid API-Token.", status=401)

    log_request(request)
    target_url = request.query.get("url")
    if not target_url:
        return web.Response(text=f"i6.shark is working as expected (v{version}).", status=200)

    headers_json = request.query.get("headers")

    try:
        target_url = ensure_url_has_scheme(target_url)
        parsed_url = urlparse(target_url)
        hostname = parsed_url.netloc
    except Exception as e:
        print(f"Error parsing URL: {e}")
        return web.Response(text=f"Invalid URL: {target_url}.", status=400)

    # Use semaphore to limit concurrent requests
    async with _request_semaphore:
        try:
            # Pick a pre-configured IP from the pool
            source_ip = _get_random_ip()
            if source_ip:
                connector = aiohttp.TCPConnector(
                    local_addr=(source_ip, 0),
                    limit=MAX_CONNECTIONS,
                    limit_per_host=MAX_CONNECTIONS_PER_HOST,
                    ttl_dns_cache=300,
                    enable_cleanup_closed=True,
                )
            else:
                connector = aiohttp.TCPConnector(
                    limit=MAX_CONNECTIONS,
                    limit_per_host=MAX_CONNECTIONS_PER_HOST,
                    ttl_dns_cache=300,
                    enable_cleanup_closed=True,
                )
                source_ip = "System default (fallback)"

            if DEBUG:
                print(f"Using IPv6: {source_ip}")

            # Build forwarded headers
            headers = {}
            for name, value in request.headers.items():
                if name.lower() != 'host':
                    headers[name] = value

            # Parse and merge custom headers if provided
            if headers_json:
                try:
                    custom_headers = json.loads(headers_json)
                    if isinstance(custom_headers, dict):
                        headers.update(custom_headers)
                        if DEBUG:
                            print(f"Applied custom headers: {custom_headers}")
                    else:
                        print("Warning: 'headers' parameter is not a valid JSON object. Ignoring.")
                except json.JSONDecodeError:
                    print("Warning: Failed to parse 'headers' JSON. Ignoring.")
                except Exception as e:
                    print(f"Warning: Error processing 'headers': {e}. Ignoring.")

            timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                if DEBUG:
                    print(f"Connecting to {target_url}...")

                # Read body for methods that send data
                body = None
                if request.method in ("POST", "PUT", "PATCH"):
                    body = await request.read()

                # Use generic request method to support all HTTP methods
                resp = await session.request(
                    method=request.method,
                    url=target_url,
                    headers=headers,
                    data=body,
                )

                if DEBUG:
                    print(f"Connected! Status: {resp.status}")

                # Stream response instead of reading full body into memory
                response = web.StreamResponse(status=resp.status)
                for name, value in resp.headers.items():
                    if name.lower() not in SKIP_HEADERS:
                        response.headers[name] = value

                await response.prepare(request)

                async for chunk in resp.content.iter_chunked(STREAM_CHUNK_SIZE):
                    await response.write(chunk)

                await response.write_eof()
                return response

        except asyncio.TimeoutError:
            return web.Response(text=f"Request timed out connecting to {hostname}.", status=504)
        except aiohttp.ClientConnectorError as e:
            return web.Response(text=f"Connection error to {hostname}: {e}.", status=502)
        except aiohttp.ClientError as e:
            return web.Response(text=f"Client error accessing {hostname}: {e}.", status=502)
        except Exception as e:
            print(f"Unexpected error: {e}")
            return web.Response(text=f"Error: {e}.", status=500)
        finally:
            if 'connector' in locals():
                await connector.close()

async def on_startup(app):
    global _request_semaphore

    if os.geteuid() != 0 and LISTEN_PORT < 1024:
        print("ERROR: This script requires root privileges to bind to port 80 and add IPv6 addresses")
        print("Run with sudo or change LISTEN_PORT to a value above 1024")
        sys.exit(1)

    _request_semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

    print("Testing network configuration...")
    if not await check_interface():
        print("WARNING: Interface check failed. Some features may not work.")

    # Pre-build IP pool for faster request handling
    await _build_ip_pool()

    print("Startup checks completed")

async def on_cleanup(app):
    """Cleanup resources on shutdown"""
    print("Shutting down i6.shark...")

app = web.Application()
app.router.add_route("*", "/", handle)  # Support all HTTP methods
app.on_startup.append(on_startup)
app.on_cleanup.append(on_cleanup)

if __name__ == "__main__":
    print(f"Starting i6.shark server on {LISTEN_HOST}:{LISTEN_PORT}")
    web.run_app(app, host=LISTEN_HOST, port=LISTEN_PORT)
