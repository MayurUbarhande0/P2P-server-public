import secrets
import hashlib
import time
import json
import asyncio
import contextlib
from typing import Dict, Optional, Set, Any, List
from dataclasses import dataclass, asdict
from enum import Enum
import logging
from models import SessionState, PeerRole

logger = logging.getLogger(__name__)

@dataclass
class SessionSecurity:
    """Security parameters for session"""
    session_id: str
    session_token: str
    created_at: float
    expires_at: float
    max_participants: int = 2
    require_mutual_auth: bool = True
    encryption_required: bool = True
    key_rotation_interval: float = 3600

@dataclass  
class PeerInfo:
    """Information about connected peer"""
    peer_id: str
    role: PeerRole
    websocket: Any
    public_key: Optional[str] = None
    last_activity: float = 0.0
    authenticated: bool = False
    capabilities: Set[str] = None

    def __post_init__(self):
        if self.capabilities is None:
            self.capabilities = set()
        if self.last_activity == 0.0:
            self.last_activity = time.time()

class SecureSessionManager:
    """Production-grade session management with cryptographic security"""
    
    def __init__(self):
        self.sessions: Dict[str, SessionSecurity] = {}
        self.session_peers: Dict[str, Dict[str, PeerInfo]] = {}
        self.session_states: Dict[str, SessionState] = {}
        self.token_to_session: Dict[str, str] = {}
        self.peer_sessions: Dict[str, str] = {}
        
        # Security configuration
        self.session_timeout = 3600  # 1 hour
        self.token_entropy_bits = 256
        self.max_sessions_per_ip = 10
        self.cleanup_interval = 300
        
        # Background task management - DO NOT create task here
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False

    async def start(self):
        """Start background cleanup task - called when event loop is running"""
        if not self._running:
            self._running = True
            self._cleanup_task = asyncio.create_task(self.periodic_cleanup())
            logger.info("🧹 Session manager background cleanup started")

    async def stop(self):
        """Stop background cleanup task"""
        self._running = False
        if self._cleanup_task:
            self._cleanup_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._cleanup_task
            logger.info("🛑 Session manager background cleanup stopped")

    def generate_secure_session_id(self) -> str:
        """Generate cryptographically secure session ID"""
        random_bytes = secrets.token_bytes(32)
        timestamp = str(time.time()).encode()
        combined = random_bytes + timestamp
        session_id = hashlib.sha256(combined).hexdigest()
        
        while session_id in self.sessions:
            random_bytes = secrets.token_bytes(32)
            combined = random_bytes + timestamp
            session_id = hashlib.sha256(combined).hexdigest()
        
        return f"session_{session_id[:32]}"

    def generate_session_token(self, session_id: str) -> str:
        """Generate secure token for session joining"""
        token_bytes = secrets.token_bytes(32)
        session_bytes = session_id.encode('utf-8')
        combined = token_bytes + session_bytes
        token = secrets.token_urlsafe(32)
        return f"tok_{token}"

    async def create_session(self, 
                           initiator_id: str,
                           expires_in_seconds: int = None,
                           max_participants: int = 2,
                           require_mutual_auth: bool = True) -> tuple[str, str]:
        """Create new secure session"""
        
        session_id = self.generate_secure_session_id()
        session_token = self.generate_session_token(session_id)
        
        created_at = time.time()
        expires_at = created_at + (expires_in_seconds or self.session_timeout)
        
        security = SessionSecurity(
            session_id=session_id,
            session_token=session_token,
            created_at=created_at,
            expires_at=expires_at,
            max_participants=max_participants,
            require_mutual_auth=require_mutual_auth,
            encryption_required=True
        )
        
        self.sessions[session_id] = security
        self.session_peers[session_id] = {}
        self.session_states[session_id] = SessionState.PENDING
        self.token_to_session[session_token] = session_id
        
        logger.info(f"✅ Created secure session {session_id} with token {session_token[:16]}...")
        return session_id, session_token

    async def join_session_by_token(self,
                                  token: str,
                                  joiner_id: str,
                                  websocket: Any,
                                  role: PeerRole = PeerRole.JOINER) -> Optional[str]:
        """Join session using secure token"""
        
        if not token.startswith("tok_") or len(token) < 16:
            logger.warning(f"❌ Invalid token format from {joiner_id}")
            return None
        
        session_id = self.token_to_session.get(token)
        if not session_id:
            logger.warning(f"❌ Unknown token {token[:16]}... from {joiner_id}")
            return None
        
        session = self.sessions.get(session_id)
        if not session:
            logger.error(f"❌ Session {session_id} not found")
            return None
        
        current_time = time.time()
        if current_time > session.expires_at:
            logger.warning(f"⏰ Expired session {session_id}")
            await self.cleanup_session(session_id)
            return None
        
        current_peers = self.session_peers.get(session_id, {})
        if len(current_peers) >= session.max_participants:
            logger.warning(f"🚫 Session {session_id} at capacity")
            return None
        
        peer_info = PeerInfo(
            peer_id=joiner_id,
            role=role,
            websocket=websocket,
            last_activity=current_time
        )
        
        current_peers[joiner_id] = peer_info
        self.peer_sessions[joiner_id] = session_id
        
        if len(current_peers) == session.max_participants:
            self.session_states[session_id] = SessionState.NEGOTIATING
        
        logger.info(f"✅ Peer {joiner_id} joined session {session_id}")
        return session_id

    async def store_public_key(self, session_id: str, party: str, public_key: str) -> bool:
        """Store public key for peer authentication"""
        try:
            peers = self.session_peers.get(session_id, {})
            
            # Map party names to roles
            role_mapping = {
                "sender": ["initiator", "sender"],
                "receiver": ["joiner", "receiver"]
            }
            
            target_roles = role_mapping.get(party, [party])
            
            for peer_info in peers.values():
                # Check both role enum and string representation
                peer_role_str = str(peer_info.role).lower()
                if any(role in peer_role_str for role in target_roles):
                    peer_info.public_key = public_key
                    peer_info.authenticated = True
                    peer_info.last_activity = time.time()
                    logger.info(f"🔑 Stored public key for {party} (role: {peer_info.role}) in session {session_id}")
                    return True
                    
            logger.warning(f"⚠️ No peer found for party '{party}' in session {session_id}")
            return False
            
        except Exception as e:
            logger.error(f"❌ Failed to store public key: {e}")
            return False



    async def establish_session(self, session_id: str) -> bool:
        """Mark session as fully established"""
        session = self.sessions.get(session_id)
        peers = self.session_peers.get(session_id, {})
        
        if not session or not peers:
            return False
        
        if len(peers) != session.max_participants:
            return False
        
        if session.require_mutual_auth:
            if not all(p.authenticated for p in peers.values()):
                return False
        
        self.session_states[session_id] = SessionState.ACTIVE
        
        # Clean up session token (one-time use)
        if session.session_token in self.token_to_session:
            del self.token_to_session[session.session_token]
        
        logger.info(f"🎉 Session {session_id} established and active")
        return True

    async def get_peer_by_role(self, session_id: str, role: str) -> Optional[PeerInfo]:
        """Find peer by role in session"""
        peers = self.session_peers.get(session_id, {})
        for peer in peers.values():
            if peer.role == role:
                return peer
        return None

    async def update_peer_activity(self, session_id: str, peer_id: str):
        """Update peer activity timestamp"""
        peers = self.session_peers.get(session_id, {})
        if peer_id in peers:
            peers[peer_id].last_activity = time.time()

    async def get_active_sessions(self) -> List[str]:
        """Get list of active session IDs"""
        current_time = time.time()
        active = []
        for session_id, session in self.sessions.items():
            if current_time <= session.expires_at:
                active.append(session_id)
        return active

    async def get_session_state(self, session_id: str) -> Optional[SessionState]:
        """Get current session state"""
        return self.session_states.get(session_id)

    async def cleanup_session(self, session_id: str):
        """Clean up session data"""
        peers = self.session_peers.get(session_id, {})
        for peer_id in peers:
            self.peer_sessions.pop(peer_id, None)
        
        session = self.sessions.pop(session_id, None)
        self.session_peers.pop(session_id, None)
        self.session_states.pop(session_id, None)
        
        if session and session.session_token in self.token_to_session:
            del self.token_to_session[session.session_token]
        
        logger.info(f"🧹 Session {session_id} cleaned up")

    async def delete_session(self, session_id: str):
        """Delete session (alias for cleanup)"""
        await self.cleanup_session(session_id)

    async def periodic_cleanup(self):
        """Periodic cleanup of expired sessions"""
        while self._running:
            try:
                current_time = time.time()
                expired_sessions = []
                
                for session_id, session in self.sessions.items():
                    if current_time > session.expires_at:
                        expired_sessions.append(session_id)
                
                for session_id in expired_sessions:
                    await self.cleanup_session(session_id)
                
                if expired_sessions:
                    logger.info(f"🧹 Cleaned up {len(expired_sessions)} expired sessions")
                
            except Exception as e:
                logger.error(f"❌ Cleanup error: {e}")
            
            await asyncio.sleep(self.cleanup_interval)
