# main.py
import asyncio
import json
import logging
import time
from typing import Dict, List, Optional, Tuple, Union

import httpx
import redis.asyncio as redis
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from redis.commands.timeseries.info import TSInfo
from redis.exceptions import ResponseError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("ddos_protection")

# Initialize FastAPI app
app = FastAPI(title="DDoS Protection API", version="1.0.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Redis connection
REDIS_HOST = "redis"  # Docker service name
REDIS_PORT = 6379
REDIS_PASSWORD = None  # Add password in production

# Anomaly detection configuration
WINDOW_SIZE = 60  # seconds
ZSCORE_THRESHOLD = 3.0  # Standard deviations
MIN_DATA_POINTS = 30  # Minimum data points required for z-score calculation

# Rate limiting configuration
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 1000  # requests per window per IP

# Threat intelligence API configuration
THREAT_INTEL_API_URL = "https://api.threatintelligence.example/v1/check"
THREAT_INTEL_API_KEY = "your-api-key"  

# Cloudflare API configuration
CLOUDFLARE_API_URL = "https://api.cloudflare.com/client/v4"
CLOUDFLARE_API_KEY = "your-cloudflare-api-key"  
CLOUDFLARE_EMAIL = "your-email@example.com"  
CLOUDFLARE_ZONE_ID = "your-zone-id"  

# Models
class AnomalyDetectionResult(BaseModel):
    timestamp: float
    metric: str
    value: float
    zscore: float
    is_anomaly: bool
    threshold: float


class VerificationRequest(BaseModel):
    clientIP: str
    userAgent: str
    cookies: Optional[Dict[str, str]] = None
    headers: Optional[Dict[str, str]] = None


class MitigationAction(BaseModel):
    action_type: str = Field(..., description="Type of mitigation action: block, challenge, or monitor")
    target: str = Field(..., description="Target of the action (IP, range, ASN, country)")
    duration: int = Field(300, description="Duration of the action in seconds")
    reason: str = Field(..., description="Reason for the mitigation action")


class ThreatIntelResult(BaseModel):
    ip: str
    risk_score: float
    categories: List[str]
    is_proxy: bool
    is_tor: bool
    is_vpn: bool
    country_code: str
    asn: int
    asn_name: str


# Redis connection pool
async def get_redis():
    redis_client = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        password=REDIS_PASSWORD,
        decode_responses=True,
    )
    try:
        yield redis_client
    finally:
        await redis_client.close()


# Initialize Redis TimeSeries keys on startup
@app.on_event("startup")
async def startup_event():
    redis_client = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        password=REDIS_PASSWORD,
        decode_responses=True,
    )
    
    # Create TimeSeries keys if they don't exist
    try:
        # Total requests per second
        await redis_client.ts().create("ddos:total_rps", retention_msecs=86400000)  
        await redis_client.ts().create("ddos:total_rps:avg", retention_msecs=86400000)
        await redis_client.ts().create("ddos:total_rps:std", retention_msecs=86400000)
        
        # Requests per second by path
        await redis_client.ts().create("ddos:path_rps", retention_msecs=86400000)
        await redis_client.ts().create("ddos:path_rps:avg", retention_msecs=86400000)
        await redis_client.ts().create("ddos:path_rps:std", retention_msecs=86400000)
        
        # Requests per second by IP
        await redis_client.ts().create("ddos:ip_rps", retention_msecs=86400000)
        await redis_client.ts().create("ddos:ip_rps:avg", retention_msecs=86400000)
        await redis_client.ts().create("ddos:ip_rps:std", retention_msecs=86400000)
        
        # Response times
        await redis_client.ts().create("ddos:response_time", retention_msecs=86400000)
        await redis_client.ts().create("ddos:response_time:avg", retention_msecs=86400000)
        await redis_client.ts().create("ddos:response_time:std", retention_msecs=86400000)
        
        # Error rates
        await redis_client.ts().create("ddos:error_rate", retention_msecs=86400000)
        await redis_client.ts().create("ddos:error_rate:avg", retention_msecs=86400000)
        await redis_client.ts().create("ddos:error_rate:std", retention_msecs=86400000)
        
        logger.info("Redis TimeSeries keys created successfully")
    except ResponseError as e:
        if "already exists" not in str(e):
            logger.error(f"Error creating Redis TimeSeries keys: {e}")
    finally:
        await redis_client.close()


# Middleware to track requests and response times
@app.middleware("http")
async def track_requests(request: Request, call_next):
    # Get client IP
    client_ip = request.client.host if request.client else "unknown"
    path = request.url.path
    
    # Record start time
    start_time = time.time()
    
    # Process request
    response = await call_next(request)
    
    # Calculate response time
    response_time = time.time() - start_time
    
    # Record metrics in Redis
    redis_client = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        password=REDIS_PASSWORD,
        decode_responses=True,
    )
    
    try:
        timestamp = int(time.time() * 1000)  # Redis TimeSeries uses millisecond timestamps
        
        # Increment total RPS counter
        await redis_client.ts().add("ddos:total_rps", timestamp, 1, duplicate_policy="sum")
        
        # Increment path-specific RPS counter
        path_key = f"ddos:path:{path}"
        try:
            await redis_client.ts().add(path_key, timestamp, 1, duplicate_policy="sum")
        except ResponseError:
            await redis_client.ts().create(path_key, retention_msecs=86400000)
            await redis_client.ts().add(path_key, timestamp, 1, duplicate_policy="sum")
        
        # Increment IP-specific RPS counter
        ip_key = f"ddos:ip:{client_ip}"
        try:
            await redis_client.ts().add(ip_key, timestamp, 1, duplicate_policy="sum")
        except ResponseError:
            await redis_client.ts().create(ip_key, retention_msecs=86400000)
            await redis_client.ts().add(ip_key, timestamp, 1, duplicate_policy="sum")
        
        # Record response time
        await redis_client.ts().add("ddos:response_time", timestamp, response_time)
        
        # Record error rate (1 for error, 0 for success)
        is_error = 1 if response.status_code >= 400 else 0
        await redis_client.ts().add("ddos:error_rate", timestamp, is_error, duplicate_policy="sum")
        
    except Exception as e:
        logger.error(f"Error recording metrics: {e}")
    finally:
        await redis_client.close()
    
    return response


# Real-time Z-score anomaly detection
async def detect_anomalies(redis_client: redis.Redis, metric: str) -> AnomalyDetectionResult:
    current_time = int(time.time() * 1000)
    start_time = current_time - (WINDOW_SIZE * 1000)
    
    # Get recent data points
    try:
        data = await redis_client.ts().range(
            metric,
            from_time=start_time,
            to_time=current_time,
        )
    except ResponseError:
        logger.warning(f"TimeSeries key {metric} not found")
        return None
    
    if not data or len(data) < MIN_DATA_POINTS:
        logger.info(f"Not enough data points for {metric}")
        return None
    
    # Calculate current value (most recent data point)
    current_value = data[-1][1] if data else 0
    
    # Calculate average and standard deviation
    values = [point[1] for point in data]
    avg = sum(values) / len(values)
    std_dev = (sum((x - avg) ** 2 for x in values) / len(values)) ** 0.5
    
    # Avoid division by zero
    if std_dev == 0:
        zscore = 0
    else:
        zscore = (current_value - avg) / std_dev
    
    # Check if the value is anomalous
    is_anomaly = abs(zscore) > ZSCORE_THRESHOLD
    
    # Store the average and standard deviation for this metric
    await redis_client.ts().add(f"{metric}:avg", current_time, avg)
    await redis_client.ts().add(f"{metric}:std", current_time, std_dev)
    
    return AnomalyDetectionResult(
        timestamp=current_time / 1000,  # Convert back to seconds
        metric=metric,
        value=current_value,
        zscore=zscore,
        is_anomaly=is_anomaly,
        threshold=ZSCORE_THRESHOLD,
    )


# Check rate limits for an IP
async def check_rate_limit(redis_client: redis.Redis, ip: str) -> Tuple[bool, int]:
    current_time = int(time.time())
    key = f"ratelimit:{ip}"
    
    # Get the current count
    count = await redis_client.get(key)
    count = int(count) if count else 0
    
    # Check if the IP is rate limited
    if count >= RATE_LIMIT_MAX_REQUESTS:
        return True, count
    
    # Increment the counter
    pipe = redis_client.pipeline()
    await pipe.incr(key)
    await pipe.expire(key, RATE_LIMIT_WINDOW)
    await pipe.execute()
    
    return False, count + 1


# Check an IP against threat intelligence
async def check_threat_intel(ip: str) -> ThreatIntelResult:
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"{THREAT_INTEL_API_URL}?ip={ip}",
                headers={"Authorization": f"Bearer {THREAT_INTEL_API_KEY}"},
                timeout=2.0,  # Short timeout to avoid blocking
            )
            
            if response.status_code == 200:
                data = response.json()
                return ThreatIntelResult(**data)
            else:
                logger.warning(f"Failed to check threat intelligence for {ip}: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Error checking threat intelligence: {e}")
            return None


# Add an IP to Cloudflare's firewall
async def add_to_cloudflare_blocklist(ip: str, duration: int = 3600) -> bool:
    async with httpx.AsyncClient() as client:
        try:
            # Create a firewall rule to block the IP
            response = await client.post(
                f"{CLOUDFLARE_API_URL}/zones/{CLOUDFLARE_ZONE_ID}/firewall/rules",
                headers={
                    "X-Auth-Email": CLOUDFLARE_EMAIL,
                    "X-Auth-Key": CLOUDFLARE_API_KEY,
                    "Content-Type": "application/json",
                },
                json={
                    "description": f"DDoS Protection - Automatically blocked {ip}",
                    "action": "block",
                    "filter": {
                        "expression": f"ip.src eq {ip}",
                        "paused": False,
                    },
                    "priority": 1,
                },
            )
            
            if response.status_code in (200, 201):
                logger.info(f"Successfully added {ip} to Cloudflare blocklist")
                return True
            else:
                logger.warning(f"Failed to add {ip} to Cloudflare blocklist: {response.status_code}, {response.text}")
                return False
        except Exception as e:
            logger.error(f"Error adding IP to Cloudflare blocklist: {e}")
            return False


# Endpoint for client verification
@app.post("/api/verify", response_model=Dict[str, Union[bool, str]])
async def verify_client(
    request: VerificationRequest,
    redis_client: redis.Redis = Depends(get_redis),
):
    ip = request.clientIP
    
    # Check if the IP is already verified
    is_verified = await redis_client.get(f"verified:{ip}")
    if is_verified:
        return {"verified": True, "verification_type": "cached"}
    
    # Check rate limits
    is_limited, count = await check_rate_limit(redis_client, ip)
    if is_limited:
        return {"verified": False, "verification_type": "rate_limited"}
    
    # Check threat intelligence
    threat_intel = await check_threat_intel(ip)
    if threat_intel and threat_intel.risk_score > 70:
        # Auto-block high-risk IPs
        await add_to_cloudflare_blocklist(ip)
        await redis_client.set(f"blocked:{ip}", "threat_intel", ex=3600)
        return {"verified": False, "verification_type": "threat_intel_blocked"}
    
    # Progressive verification based on request count
    if count > 100:
        # Higher count requires CAPTCHA
        return {"verified": False, "verification_type": "captcha_required"}
    elif count > 50:
        # Medium count requires JavaScript verification
        return {"verified": False, "verification_type": "js_challenge"}
    else:
        # Low count just requires a cookie
        await redis_client.set(f"verified:{ip}", "cookie", ex=3600)
        return {"verified": True, "verification_type": "cookie"}


# Endpoint to check for anomalies
@app.get("/api/anomalies", response_model=List[AnomalyDetectionResult])
async def get_anomalies(
    redis_client: redis.Redis = Depends(get_redis),
):
    anomalies = []
    
    # Check total RPS anomalies
    total_rps_anomaly = await detect_anomalies(redis_client, "ddos:total_rps")
    if total_rps_anomaly and total_rps_anomaly.is_anomaly:
        anomalies.append(total_rps_anomaly)
    
    # Check response time anomalies
    response_time_anomaly = await detect_anomalies(redis_client, "ddos:response_time")
    if response_time_anomaly and response_time_anomaly.is_anomaly:
        anomalies.append(response_time_anomaly)
    
    # Check error rate anomalies
    error_rate_anomaly = await detect_anomalies(redis_client, "ddos:error_rate")
    if error_rate_anomaly and error_rate_anomaly.is_anomaly:
        anomalies.append(error_rate_anomaly)
    
    # Check for top 10 paths by request volume
    top_paths = []
    cursor = b"0"
    pattern = "ddos:path:*"
    
    while cursor:
        cursor, keys = await redis_client.scan(cursor=cursor, match=pattern, count=100)
        for key in keys:
            if ":avg" not in key and ":std" not in key:
                path_anomaly = await detect_anomalies(redis_client, key)
                if path_anomaly and path_anomaly.is_anomaly:
                    anomalies.append(path_anomaly)
                    top_paths.append((key, path_anomaly.value))
        
        if cursor == b"0":
            break
    
    # Check for top IPs by request volume
    top_ips = []
    cursor = b"0"
    pattern = "ddos:ip:*"
    
    while cursor:
        cursor, keys = await redis_client.scan(cursor=cursor, match=pattern, count=100)
        for key in keys:
            if ":avg" not in key and ":std" not in key:
                ip_anomaly = await detect_anomalies(redis_client, key)
                if ip_anomaly and ip_anomaly.is_anomaly:
                    anomalies.append(ip_anomaly)
                    
                    # Extract IP from key
                    ip = key.split(":")[-1]
                    top_ips.append((ip, ip_anomaly.value))
        
        if cursor == b"0":
            break
    
    # Auto-block IPs with anomalous behavior
    for ip, value in top_ips:
        if value > 100:  # Threshold for automatic blocking
            await add_to_cloudflare_blocklist(ip)
            await redis_client.set(f"blocked:{ip}", "auto_anomaly", ex=3600)
            logger.info(f"Auto-blocked anomalous IP: {ip} with value {value}")
    
    return anomalies


# Endpoint to get metrics for the dashboard
@app.get("/api/metrics", response_model=Dict[str, Union[float, List[Dict[str, Union[float, str]]]]])
async def get_metrics(
    redis_client: redis.Redis = Depends(get_redis),
):
    current_time = int(time.time() * 1000)
    start_time = current_time - (3600 * 1000)  # Last hour
    
    # Get total RPS
    try:
        total_rps_data = await redis_client.ts().range(
            "ddos:total_rps",
            from_time=start_time,
            to_time=current_time,
            aggregation_type="avg",
            bucket_size_msec=60000,  # 1 minute buckets
        )
        
        total_rps = [
            {"timestamp": point[0] / 1000, "value": point[1]}
            for point in total_rps_data
        ]
    except ResponseError:
        total_rps = []
    
    # Get response times
    try:
        response_time_data = await redis_client.ts().range(
            "ddos:response_time",
            from_time=start_time,
            to_time=current_time,
            aggregation_type="avg",
            bucket_size_msec=60000,  # 1 minute buckets
        )
        
        response_times = [
            {"timestamp": point[0] / 1000, "value": point[1]}
            for point in response_time_data
        ]
    except ResponseError:
        response_times = []
    
    # Get error rates
    try:
        error_rate_data = await redis_client.ts().range(
            "ddos:error_rate",
            from_time=start_time,
            to_time=current_time,
            aggregation_type="avg",
            bucket_size_msec=60000,  # 1 minute buckets
        )
        
        error_rates = [
            {"timestamp": point[0] / 1000, "value": point[1] * 100}  # Convert to percentage
            for point in error_rate_data
        ]
    except ResponseError:
        error_rates = []
    
    # Get top paths
    top_paths = []
    cursor = b"0"
    pattern = "ddos:path:*"
    path_values = []
    
    while cursor:
        cursor, keys = await redis_client.scan(cursor=cursor, match=pattern, count=100)
        for key in keys:
            if ":avg" not in key and ":std" not in key:
                try:
                    path_data = await redis_client.ts().range(
                        key,
                        from_time=start_time,
                        to_time=current_time,
                        aggregation_type="sum",
                        bucket_size_msec=3600000,  # 1 hour bucket
                    )
                    
                    if path_data:
                        path = key.replace("ddos:path:", "")
                        value = path_data[0][1]
                        path_values.append((path, value))
                except ResponseError:
                    continue
        
        if cursor == b"0":
            break
    
    # Sort paths by request count and take top 10
    path_values.sort(key=lambda x: x[1], reverse=True)
    top_paths = [{"path": path, "requests": value} for path, value in path_values[:10]]
    
    # Get top IPs
    top_ips = []
    cursor = b"0"
    pattern = "ddos:ip:*"
    ip_values = []
    
    while cursor:
        cursor, keys = await redis_client.scan(cursor=cursor, match=pattern, count=100)
        for key in keys:
            if ":avg" not in key and ":std" not in key:
                try:
                    ip_data = await redis_client.ts().range(
                        key,
                        from_time=start_time,
                        to_time=current_time,
                        aggregation_type="sum",
                        bucket_size_msec=3600000,  # 1 hour bucket
                    )
                    
                    if ip_data:
                        ip = key.replace("ddos:ip:", "")
                        value = ip_data[0][1]
                        ip_values.append((ip, value))
                except ResponseError:
                    continue
        
        if cursor == b"0":
            break
    
    # Sort IPs by request count and take top 10
    ip_values.sort(key=lambda x: x[1], reverse=True)
    top_ips = [{"ip": ip, "requests": value} for ip, value in ip_values[:10]]
    
    # Get blocked IPs
    blocked_ips = []
    cursor = b"0"
    pattern = "blocked:*"
    
    while cursor:
        cursor, keys = await redis_client.scan(cursor=cursor, match=pattern, count=100)
        for key in keys:
            ip = key.replace("blocked:", "")
            reason = await redis_client.get(key)
            blocked_ips.append({"ip": ip, "reason": reason})
        
        if cursor == b"0":
            break
    
    return {
        "total_rps": total_rps,
        "response_times": response_times,
        "error_rates": error_rates,
        "top_paths": top_paths,
        "top_ips": top_ips,
        "blocked_ips": blocked_ips,
    }


# Endpoint to manually add mitigation action
@app.post("/api/mitigate", response_model=Dict[str, bool])
async def add_mitigation(
    action: MitigationAction,
    redis_client: redis.Redis = Depends(get_redis),
):
    if action.action_type == "block":
        # Block the IP in Cloudflare
        success = await add_to_cloudflare_blocklist(action.target, action.duration)
        if success:
            await redis_client.set(f"blocked:{action.target}", action.reason, ex=action.duration)
        return {"success": success}
    elif action.action_type == "challenge":
        # Add a challenge rule in Cloudflare
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    f"{CLOUDFLARE_API_URL}/zones/{CLOUDFLARE_ZONE_ID}/firewall/rules",
                    headers={
                        "X-Auth-Email": CLOUDFLARE_EMAIL,
                        "X-Auth-Key": CLOUDFLARE_API_KEY,
                        "Content-Type": "application/json",
                    },
                    json={
                        "description": f"DDoS Protection - Challenge {action.target}",
                        "action": "challenge",
                        "filter": {
                            "expression": f"ip.src eq {action.target}",
                            "paused": False,
                        },
                        "priority": 2,
                    },
                )
                
                success = response.status_code in (200, 201)
                if success:
                    await redis_client.set(f"challenged:{action.target}", action.reason, ex=action.duration)
                return {"success": success}
            except Exception as e:
                logger.error(f"Error adding challenge rule: {e}")
                return {"success": False}
    else:
        # Just monitor the IP
        await redis_client.set(f"monitored:{action.target}", action.reason, ex=action.duration)
        return {"success": True}


# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)