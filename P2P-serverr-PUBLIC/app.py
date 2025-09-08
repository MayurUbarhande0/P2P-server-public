#!/usr/bin/env python3
"""
Advanced P2P Cloud Storage Broker - Production Server
Features: Token-based sessions, E2E encryption, Zero-knowledge relay
"""
import asyncio
import json
import logging
import sys
import time
import traceback
import secrets
from contextlib import asynccontextmanager
from typing import Dict, Set, Any

# FastAPI imports
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Your application imports
from config import settings
from models import *
from session_manager import SecureSessionManager
from connection_manager import EnhancedConnectionManager

# Fix Windows asyncio connection issues
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# Configure Windows-compatible logging (NO EMOJIS to fix encoding issues)
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL if hasattr(settings, 'LOG_LEVEL') else 'INFO'),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(getattr(settings, 'LOG_FILE', 'p2p_broker.log'), mode='a', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

# Global managers
session_manager = SecureSessionManager()
connection_manager = EnhancedConnectionManager(session_manager)

# CRITICAL FIX: Proper FastAPI WebSocket message sending
async def send_websocket_json(websocket: WebSocket, message: Dict[str, Any], message_type: str = "MESSAGE") -> bool:
    """
    Send JSON message using proper FastAPI WebSocket method.
    This fixes the 'string indices must be integers' error.
    """
    try:
        # Validate input
        if not isinstance(message, dict):
            logger.error(f"Message must be dict, got {type(message)}: {message}")
            return False
        
        # Add broker metadata for tracking
        if "_broker_timestamp" not in message:
            message["_broker_timestamp"] = time.time()
        if "_broker_version" not in message:
            message["_broker_version"] = "3.0.0"
        
        # Use FastAPI's send_text method with JSON string (CRITICAL FIX)
        json_string = json.dumps(message, ensure_ascii=False, separators=(',', ':'))
        await websocket.send_text(json_string)  # <- This is the key fix
        
        logger.info(f"SUCCESS SENT {message_type}: {json_string[:100]}...")
        return True
        
    except Exception as e:
        logger.error(f"SEND FAILED for {message_type}: {e}")
        logger.error(f"Message type: {type(message)}")
        logger.error(f"Message content: {message}")
        return False

async def send_error_message(websocket: WebSocket, error_code: str, error_message: str) -> bool:
    """Send standardized error message"""
    error_response = {
        "type": "ERROR",
        "error_code": error_code,
        "message": error_message,
        "timestamp": time.time()
    }
    return await send_websocket_json(websocket, error_response, f"ERROR_{error_code}")

async def broadcast_to_session_peers(session_id: str, message: Dict[str, Any], message_type: str = "BROADCAST") -> int:
    """Broadcast message to all peers in session using fixed send method"""
    peers = session_manager.session_peers.get(session_id, {})
    success_count = 0
    
    if not peers:
        logger.warning(f"No peers found for session {session_id}")
        return 0
    
    # Serialize once for efficiency
    try:
        json_string = json.dumps(message, ensure_ascii=False, separators=(',', ':'))
    except Exception as e:
        logger.error(f"Broadcast serialization failed: {e}")
        return 0
    
    # Send to all peers using send_text
    for peer_id, peer_info in peers.items():
        try:
            await peer_info.websocket.send_text(json_string)  # <- Fixed method
            success_count += 1
            logger.debug(f"Broadcast sent to {peer_id}")
        except Exception as e:
            logger.error(f"Broadcast failed to {peer_id}: {e}")
    
    logger.info(f"Broadcast {message_type} sent to {success_count}/{len(peers)} peers in session {session_id}")
    return success_count

# CRITICAL FIX: Define lifespan BEFORE FastAPI constructor
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Advanced application lifecycle management"""
    # Startup
    logger.info("Starting Advanced P2P Broker Server v3.0.0...")
    logger.info(f"Server configuration: {getattr(settings, 'HOST', '0.0.0.0')}:{getattr(settings, 'PORT', 8000)}")
    logger.info(f"Production mode: {getattr(settings, 'is_production', lambda: True)()}")
    logger.info("Security features: Token-based sessions, E2E encryption, Advanced error handling")
    
    try:
        await session_manager.start()
        logger.info("Session manager background tasks started")
        
        # Health check on startup
        active_sessions = await session_manager.get_active_sessions()
        logger.info(f"Initial state: {len(active_sessions)} active sessions")
        
        # Initialize connection manager state
        logger.info("Connection manager initialized")
        
        # Log system capabilities
        logger.info("Available features: CREATE_INVITATION, JOIN_BY_TOKEN, KEY_EXCHANGE, ENCRYPTED_MESSAGE")
        logger.info("Backwards compatibility: REGISTER, JOIN_SESSION enabled")
        
    except Exception as e:
        logger.error(f"Startup failed: {e}")
        traceback.print_exc()
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down Advanced P2P Broker Server...")
    try:
        # Clean up all active sessions
        active_sessions = await session_manager.get_active_sessions()
        for session_id in active_sessions:
            await session_manager.cleanup_session(session_id)
        
        await session_manager.stop()
        logger.info("Session manager background tasks stopped gracefully")
        logger.info("All sessions cleaned up")
    except Exception as e:
        logger.error(f"Shutdown error: {e}")

# NOW create FastAPI app with lifespan defined
app = FastAPI(
    title="Advanced P2P Cloud Storage Broker",
    description="Production-grade signaling server for P2P file sharing with E2E encryption",
    version="3.0.0",
    lifespan=lifespan  # Now this will work because lifespan is defined above
)

# Add CORS middleware for Android app support
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure more restrictively in production
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Advanced global error handler
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error(f"Global exception: {exc}")
    logger.error(f"Request: {request.url if hasattr(request, 'url') else 'N/A'}")
    traceback.print_exc()
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "error_type": type(exc).__name__,
            "timestamp": time.time(),
            "version": "3.0.0"
        }
    )

@app.get("/")
async def root():
    """Enhanced root endpoint with comprehensive server information"""
    return {
        "message": "Advanced P2P Cloud Storage Broker Server",
        "version": "3.0.0",
        "status": "operational",
        "features": [
            "token_based_sessions",
            "secure_key_exchange", 
            "e2e_encryption",
            "advanced_error_handling",
            "production_logging",
            "session_recovery",
            "windows_compatible",
            "zero_knowledge_relay",
            "async_fixed"
        ],
        "message_types_supported": [
            "CREATE_INVITATION",
            "JOIN_BY_TOKEN", 
            "KEY_EXCHANGE",
            "ENCRYPTED_MESSAGE",
            "REGISTER",
            "JOIN_SESSION",
            "PING"
        ],
        "endpoints": {
            "websocket": "/ws",
            "health": "/health",
            "stats": "/stats"
        },
        "security": {
            "encryption": "AES-256-GCM",
            "key_exchange": "ECDH-P256",
            "token_entropy": "256-bit",
            "session_timeout": "1 hour"
        },
        "timestamp": time.time()
    }

@app.get("/health")
async def health_check():
    """Advanced health check with detailed system status"""
    try:
        start_time = time.time()
        active_sessions = await session_manager.get_active_sessions()
        
        # Calculate detailed metrics
        total_connections = 0
        session_states = {}
        expired_count = 0
        
        for session_id in active_sessions:
            peers = session_manager.session_peers.get(session_id, {})
            total_connections += len(peers)
            
            # Check session state
            state = await session_manager.get_session_state(session_id)
            state_str = str(state) if state else "unknown"
            session_states[state_str] = session_states.get(state_str, 0) + 1
            
            # Check expiration
            session_info = session_manager.sessions.get(session_id)
            if session_info and time.time() > session_info.expires_at:
                expired_count += 1
        
        health_check_time = time.time() - start_time
        
        return {
            "status": "healthy",
            "version": "3.0.0",
            "timestamp": time.time(),
            "uptime": time.time(),
            "performance": {
                "health_check_ms": round(health_check_time * 1000, 2),
                "active_sessions": len(active_sessions),
                "total_connections": total_connections,
                "expired_sessions": expired_count,
                "session_states": session_states,
                "average_peers_per_session": round(total_connections / max(len(active_sessions), 1), 2)
            },
            "features": {
                "security_enabled": True,
                "encryption_ready": True,
                "background_tasks_running": session_manager._running,
                "error_handling": "advanced",
                "windows_compatible": True,
                "websocket_fix_applied": True,
                "async_runtime_fix_applied": True
            },
            "system": {
                "python_version": sys.version.split()[0],
                "platform": sys.platform,
                "asyncio_policy": str(type(asyncio.get_event_loop_policy()).__name__)
            }
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        traceback.print_exc()
        return {
            "status": "unhealthy",
            "error": str(e),
            "error_type": type(e).__name__,
            "timestamp": time.time(),
            "version": "3.0.0"
        }

@app.get("/stats")
async def get_comprehensive_stats():
    """Advanced statistics endpoint with detailed metrics"""
    try:
        active_sessions = await session_manager.get_active_sessions()
        
        # Detailed session analysis
        session_details = []
        total_connections = 0
        connection_states = {"active": 0, "idle": 0, "expired": 0}
        
        for session_id in active_sessions:
            peers = session_manager.session_peers.get(session_id, {})
            peer_count = len(peers)
            total_connections += peer_count
            
            session_info = session_manager.sessions.get(session_id)
            state = await session_manager.get_session_state(session_id)
            
            # Determine connection state
            if session_info:
                if time.time() > session_info.expires_at:
                    connection_states["expired"] += 1
                elif peer_count >= 2:
                    connection_states["active"] += 1
                else:
                    connection_states["idle"] += 1
            
            session_details.append({
                "session_id": session_id[:16] + "...",  # Truncated for privacy
                "peer_count": peer_count,
                "state": str(state) if state else "unknown",
                "created_at": session_info.created_at if session_info else None,
                "expires_at": session_info.expires_at if session_info else None,
                "age_seconds": time.time() - session_info.created_at if session_info else None,
                "time_remaining": session_info.expires_at - time.time() if session_info else None
            })
        
        # Sort by creation time (newest first)
        session_details.sort(key=lambda x: x.get("created_at", 0), reverse=True)
        
        return {
            "timestamp": time.time(),
            "version": "3.0.0",
            "summary": {
                "active_sessions": len(active_sessions),
                "total_connections": total_connections,
                "average_peers_per_session": round(total_connections / max(len(active_sessions), 1), 2),
                "connection_states": connection_states
            },
            "sessions": session_details[:10],  # Limit to 10 most recent
            "system": {
                "background_cleanup_running": session_manager._running,
                "connection_manager_operational": True,
                "security_features_enabled": True,
                "websocket_send_method": "send_text (fixed)",
                "error_handling_level": "advanced",
                "async_runtime_errors": "fixed"
            },
            "performance": {
                "session_cleanup_interval": 300,
                "token_entropy_bits": 256,
                "default_session_timeout": 3600
            }
        }
    except Exception as e:
        logger.error(f"Stats generation failed: {e}")
        traceback.print_exc()
        return {
            "error": str(e),
            "error_type": type(e).__name__,
            "timestamp": time.time(),
            "version": "3.0.0"
        }

@app.websocket("/ws")
async def advanced_websocket_endpoint(websocket: WebSocket):
    """
    Advanced WebSocket endpoint with comprehensive error handling and FIXED async/await
    """
    
    # Connection setup with detailed logging
    client_info = f"{websocket.client.host}:{websocket.client.port}"
    connection_id = f"conn_{int(time.time())}_{websocket.client.port}"
    
    logger.info(f"New WebSocket connection: {client_info} ({connection_id})")
    
    try:
        await connection_manager.connect(websocket)
        logger.info(f"WebSocket accepted: {client_info}")
    except Exception as e:
        logger.error(f"Connection setup failed for {client_info}: {e}")
        return
    
    # Connection state tracking
    current_session_id = None
    current_peer_id = None
    current_role = None
    message_count = 0
    connection_start_time = time.time()
    
    try:
        while True:
            try:
                # Receive message with timeout protection
                data = await asyncio.wait_for(websocket.receive_text(), timeout=300.0)
                message_count += 1
                
                logger.info(f"Message #{message_count} from {client_info}: {data[:200]}...")
                
            except asyncio.TimeoutError:
                logger.warning(f"Timeout waiting for message from {client_info} after {message_count} messages")
                await send_error_message(websocket, "TIMEOUT", "Connection timeout - no activity")
                break
            except WebSocketDisconnect:
                logger.info(f"Client {client_info} disconnected gracefully")
                break
            except Exception as e:
                logger.error(f"Receive error from {client_info}: {e}")
                break
            
            # Parse JSON with comprehensive error handling
            try:
                message_data = json.loads(data)
                if not isinstance(message_data, dict):
                    await send_error_message(websocket, "INVALID_FORMAT", "Message must be JSON object")
                    continue
                    
            except json.JSONDecodeError as e:
                logger.warning(f"Invalid JSON from {client_info}: {e}")
                await send_error_message(websocket, "INVALID_JSON", f"Invalid JSON format: {str(e)}")
                continue
            except Exception as e:
                logger.error(f"JSON parsing error from {client_info}: {e}")
                await send_error_message(websocket, "PARSE_ERROR", "Failed to parse message")
                continue
            
            # Extract and validate message type
            msg_type = message_data.get('type', 'UNKNOWN')
            logger.info(f"Processing {msg_type} from {client_info}")
            
            # Handle CREATE_INVITATION
            if msg_type == "CREATE_INVITATION":
                try:
                    expires_in = message_data.get('expires_in_minutes', 30)
                    intent = message_data.get('intent', 'send_files')
                    capabilities = message_data.get('capabilities', [])
                    
                    # Validate parameters
                    if not isinstance(expires_in, (int, float)) or expires_in <= 0 or expires_in > 1440:
                        await send_error_message(websocket, "INVALID_EXPIRY", "Expiry must be 1-1440 minutes")
                        continue
                    
                    # Create session with advanced parameters
                    peer_id = f"peer_{websocket.client.host}_{int(time.time())}_{secrets.token_hex(4)}"
                    session_id, token = await session_manager.create_session(
                        peer_id,
                        expires_in_seconds=int(expires_in * 60),
                        max_participants=2,
                        require_mutual_auth=True
                    )
                    
                    # Add creator to session
                    from models import PeerRole
                    join_result = await session_manager.join_session_by_token(
                        token, peer_id, websocket, PeerRole.INITIATOR
                    )
                    
                    if not join_result:
                        await send_error_message(websocket, "SESSION_JOIN_FAILED", "Failed to join created session")
                        continue
                    
                    # Update connection state
                    current_session_id = session_id
                    current_peer_id = peer_id
                    current_role = "initiator"
                    
                    # Create comprehensive response
                    response = {
                        "type": "INVITATION_CREATED",
                        "token": token,
                        "session_id": session_id,
                        "expires_at": time.time() + (expires_in * 60),
                        "expires_in_minutes": expires_in,
                        "share_url": f"p2pshare://{token}",
                        "qr_data": token,
                        "intent": intent,
                        "capabilities": capabilities,
                        "security": {
                            "encryption_enabled": True,
                            "forward_secrecy": True,
                            "zero_knowledge_broker": True,
                            "key_exchange_algorithm": "ECDH-P256",
                            "encryption_algorithm": "AES-256-GCM"
                        },
                        "connection_info": {
                            "session_max_participants": 2,
                            "mutual_auth_required": True,
                            "session_timeout_seconds": expires_in * 60
                        },
                        "timestamp": time.time()
                    }
                    
                    # Send response using fixed method
                    success = await send_websocket_json(websocket, response, "INVITATION_CREATED")
                    if success:
                        logger.info(f"Created invitation for {client_info}: token={token[:16]}..., session={session_id}")
                    
                except Exception as e:
                    logger.error(f"CREATE_INVITATION error for {client_info}: {e}")
                    traceback.print_exc()
                    await send_error_message(websocket, "INVITATION_ERROR", f"Failed to create invitation: {str(e)}")
            
            # Handle JOIN_BY_TOKEN
            elif msg_type == "JOIN_BY_TOKEN":
                try:
                    token = message_data.get('token', '').strip() if isinstance(message_data.get('token'), str) else message_data.get('token', '')
                    intent = message_data.get('intent', 'receive_files')
                    capabilities = message_data.get('capabilities', [])
                    
                    # Validate token
                    if not token:
                        await send_error_message(websocket, "MISSING_TOKEN", "Token is required")
                        continue
                    
                    if not str(token).startswith("tok_") or len(str(token)) < 20:
                        await send_error_message(websocket, "INVALID_TOKEN_FORMAT", "Invalid token format")
                        continue
                    
                    # Attempt to join session
                    peer_id = f"peer_{websocket.client.host}_{int(time.time())}_{secrets.token_hex(4)}"
                    from models import PeerRole
                    session_id = await session_manager.join_session_by_token(
                        token, peer_id, websocket, PeerRole.JOINER
                    )
                    
                    if session_id:
                        # Update connection state
                        current_session_id = session_id
                        current_peer_id = peer_id
                        current_role = "joiner"
                        
                        # Send success response
                        join_response = {
                            "type": "JOINED_SESSION",
                            "session_id": session_id,
                            "role": current_role,
                            "intent": intent,
                            "capabilities": capabilities,
                            "security": {
                                "encryption_enabled": True,
                                "peer_verified": True,
                                "session_secured": True,
                                "mutual_auth_required": True
                            },
                            "connection_info": {
                                "peer_role": "joiner",
                                "session_state": "negotiating",
                                "next_step": "key_exchange"
                            },
                            "timestamp": time.time()
                        }
                        
                        success = await send_websocket_json(websocket, join_response, "JOINED_SESSION")
                        if success:
                            logger.info(f"{client_info} joined session {session_id}")
                        
                        # Check if session is complete and broadcast
                        if connection_manager.is_session_complete(session_id):
                            session_ready_msg = {
                                "type": "SESSION_READY",
                                "session_id": session_id,
                                "message": "Both parties connected - ready for key exchange",
                                "participants": 2,
                                "security_level": "maximum",
                                "encryption_ready": True,
                                "next_steps": [
                                    "Perform ECDH key exchange",
                                    "Establish encrypted channel", 
                                    "Begin secure file transfer"
                                ],
                                "timestamp": time.time()
                            }
                            
                            broadcast_count = await broadcast_to_session_peers(session_id, session_ready_msg, "SESSION_READY")
                            logger.info(f"Session {session_id} complete - notified {broadcast_count} peers")
                    else:
                        await send_error_message(websocket, "JOIN_FAILED", "Invalid, expired, or full session token")
                        
                except Exception as e:
                    logger.error(f"JOIN_BY_TOKEN error for {client_info}: {e}")
                    traceback.print_exc()
                    await send_error_message(websocket, "JOIN_ERROR", f"Failed to join session: {str(e)}")
            
            # Handle KEY_EXCHANGE - COMPLETELY FIXED VERSION
            elif msg_type == "KEY_EXCHANGE":
                try:
                    logger.info(f"Processing KEY_EXCHANGE from {client_info}")
                    
                    # FIXED: Handle public_key as list, not string (DON'T CALL .strip() ON LISTS)
                    public_key = message_data.get('public_key', [])
                    if isinstance(public_key, str):
                        public_key = public_key.strip()
                        # If server expects base64, decode it here if needed:
                        # import base64
                        # public_key = list(base64.b64decode(public_key))
                    
                    # Validate public_key is a list
                    if not isinstance(public_key, list):
                        await send_error_message(websocket, "INVALID_PUBLIC_KEY", "public_key must be a list of bytes")
                        continue
                    
                    party = message_data.get('party', 'unknown')
                    algorithm = message_data.get('algorithm', 'ECDH-P256')
                    
                    logger.info(f"Received public key from {party}, length: {len(public_key)}")
                    
                    # Find the session for this connection
                    session_id = None
                    for sid, session in session_manager.sessions.items():
                        if current_session_id == sid:
                            session_id = sid
                            break
                    
                    if not session_id:
                        await send_error_message(websocket, "NO_SESSION", "No active session found for connection")
                        continue
                    
                    # Relay the key exchange to other clients in the session
                    relay_message = {
                        "type": "KEY_EXCHANGE",
                        "public_key": public_key,  # Send as list
                        "party": party,
                        "algorithm": algorithm,
                        "timestamp": time.time()
                    }
                    
                    # Send to other clients in the session
                    peers = session_manager.session_peers.get(session_id, {})
                    relayed_count = 0
                    
                    for peer_id, peer_info in peers.items():
                        if peer_info.websocket != websocket:
                            try:
                                await peer_info.websocket.send_text(json.dumps(relay_message))
                                relayed_count += 1
                                logger.info(f"Relayed KEY_EXCHANGE to peer {peer_id}")
                            except Exception as e:
                                logger.error(f"Failed to relay KEY_EXCHANGE to {peer_id}: {e}")
                    
                    # Send success response
                    success_response = {
                        "type": "SUCCESS",
                        "message": f"Key exchange relayed to {relayed_count} peer(s)",
                        "timestamp": time.time()
                    }
                    await send_websocket_json(websocket, success_response, "KEY_EXCHANGE_SUCCESS")
                    
                    logger.info(f"KEY_EXCHANGE processed successfully for {client_info}")
                    
                except Exception as e:
                    logger.error(f"KEY_EXCHANGE error for {client_info}: {e}")
                    error_response = {
                        "type": "ERROR",
                        "error_code": "KEY_EXCHANGE_ERROR",
                        "message": f"Key exchange failed: {str(e)}",
                        "timestamp": time.time()
                    }
                    await send_websocket_json(websocket, error_response, "ERROR_KEY_EXCHANGE_ERROR")
            
            # Handle ENCRYPTED_MESSAGE - COMPLETELY FIXED VERSION
            elif msg_type == "ENCRYPTED_MESSAGE":
                try:
                    logger.info(f"Processing ENCRYPTED_MESSAGE from {client_info}")
                    
                    # FIXED: Handle encrypted_payload as dict, not string (DON'T CALL .strip() ON DICTS)
                    encrypted_payload = message_data.get('encrypted_payload', {})
                    if isinstance(encrypted_payload, str):
                        encrypted_payload = encrypted_payload.strip()
                        # If server expects base64, decode it here if needed:
                        # import base64, json
                        # encrypted_payload = json.loads(base64.b64decode(encrypted_payload).decode('utf-8'))
                    
                    # Validate encrypted_payload is a dict
                    if not isinstance(encrypted_payload, dict):
                        await send_error_message(websocket, "INVALID_ENCRYPTED_PAYLOAD", "encrypted_payload must be a dict")
                        continue
                    
                    message_type_inner = message_data.get('message_type', 'UNKNOWN')
                    encryption_algorithm = message_data.get('encryption_algorithm', 'AES-256-GCM')
                    
                    logger.info(f"Encrypted message type: {message_type_inner}, algorithm: {encryption_algorithm}")
                    
                    # Find the session for this connection
                    session_id = None
                    for sid, session in session_manager.sessions.items():
                        if current_session_id == sid:
                            session_id = sid
                            break
                    
                    if not session_id:
                        await send_error_message(websocket, "NO_SESSION", "No active session found for connection")
                        continue
                    
                    # Relay the encrypted message to other clients in the session
                    relay_message = {
                        "type": "ENCRYPTED_MESSAGE",
                        "encrypted_payload": encrypted_payload,  # Send as dict
                        "message_type": message_type_inner,
                        "encryption_algorithm": encryption_algorithm,
                        "timestamp": time.time()
                    }
                    
                    # Send to other clients in the session
                    peers = session_manager.session_peers.get(session_id, {})
                    relayed_count = 0
                    
                    for peer_id, peer_info in peers.items():
                        if peer_info.websocket != websocket:
                            try:
                                await peer_info.websocket.send_text(json.dumps(relay_message))
                                relayed_count += 1
                                logger.info(f"Relayed ENCRYPTED_MESSAGE to peer {peer_id}")
                            except Exception as e:
                                logger.error(f"Failed to relay ENCRYPTED_MESSAGE to {peer_id}: {e}")
                    
                    if relayed_count == 0:
                        logger.warning("No other clients in session to relay message to")
                    
                    # Send success response
                    success_response = {
                        "type": "SUCCESS",
                        "message": f"Encrypted message relayed to {relayed_count} client(s)",
                        "timestamp": time.time()
                    }
                    await send_websocket_json(websocket, success_response, "ENCRYPTED_MESSAGE_SUCCESS")
                    
                    logger.info(f"ENCRYPTED_MESSAGE processed successfully for {client_info}")
                    
                except Exception as e:
                    logger.error(f"ENCRYPTED_MESSAGE error for {client_info}: {e}")
                    error_response = {
                        "type": "ERROR",
                        "error_code": "ENCRYPTED_RELAY_ERROR",
                        "message": f"Encrypted message relay failed: {str(e)}",
                        "timestamp": time.time()
                    }
                    await send_websocket_json(websocket, error_response, "ERROR_ENCRYPTED_RELAY_ERROR")
            
            # Handle PING
            elif msg_type == "PING":
                try:
                    ping_id = message_data.get('id', f"ping_{int(time.time())}")
                    
                    pong_response = {
                        "type": "PONG",
                        "id": ping_id,
                        "server_time": time.time(),
                        "session_id": current_session_id,
                        "connection_health": "good",
                        "connection_uptime": time.time() - connection_start_time,
                        "message_count": message_count,
                        "server_version": "3.0.0",
                        "timestamp": time.time()
                    }
                    
                    await send_websocket_json(websocket, pong_response, "PONG")
                    logger.debug(f"Pong sent to {client_info}")
                    
                except Exception as e:
                    logger.error(f"PING error for {client_info}: {e}")
                    await send_error_message(websocket, "PING_ERROR", "Failed to process ping")
            
            # Handle unknown message types
            else:
                logger.warning(f"Unknown message type '{msg_type}' from {client_info}")
                await send_error_message(websocket, "UNKNOWN_MESSAGE_TYPE", 
                                       f"Unknown message type: {msg_type}. Supported types: CREATE_INVITATION, JOIN_BY_TOKEN, KEY_EXCHANGE, ENCRYPTED_MESSAGE, PING")
            
            # Update peer activity if in session
            if current_session_id and current_peer_id:
                try:
                    await session_manager.update_peer_activity(current_session_id, current_peer_id)
                except Exception as e:
                    logger.debug(f"Failed to update peer activity: {e}")
    
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected normally: {client_info} after {message_count} messages")
    except Exception as e:
        logger.error(f"WebSocket error for {client_info}: {e}")
        traceback.print_exc()
    finally:
        # Comprehensive cleanup
        connection_duration = time.time() - connection_start_time
        try:
            await connection_manager.disconnect(websocket)
            
            # Clean up session if this was the last peer
            if current_session_id:
                remaining_connections = connection_manager.get_session_connection_count(current_session_id)
                if remaining_connections == 0:
                    await session_manager.cleanup_session(current_session_id)
                    logger.info(f"Cleaned up empty session {current_session_id}")
                else:
                    logger.info(f"Session {current_session_id} still has {remaining_connections} connections")
            
            logger.info(f"Connection cleanup complete for {client_info}: {message_count} messages over {connection_duration:.1f}s")
            
        except Exception as cleanup_error:
            logger.error(f"Cleanup error for {client_info}: {cleanup_error}")

# CRITICAL: Use PORT environment variable from Render
if __name__ == "__main__":
    import uvicorn
    import os
    
    logger.info("Starting Advanced P2P Broker Server with Production Configuration...")
    logger.info("Features: Windows-compatible, Fixed WebSocket sending, Production logging")
    logger.info("Security: Token-based sessions, E2E encryption, Zero-knowledge relay")
    
    # CRITICAL: Use PORT environment variable from Render
    port = int(os.getenv("PORT", 8000))
    host = "0.0.0.0"  # Required for Render
    
    logger.info(f"Server: {host}:{port}")
    logger.info("WebSocket Fix: Using send_text() method")
    logger.info("RENDER DEPLOYMENT: Using production configuration")
    
    uvicorn.run(
        "app:app",
        host=host,
        port=port,
        reload=False,  # Disable in production
        log_level="info",
        access_log=True
    )
