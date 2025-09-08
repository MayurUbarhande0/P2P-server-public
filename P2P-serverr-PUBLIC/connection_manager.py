import logging
import asyncio
from typing import Dict, Optional, Set
from fastapi import WebSocket

logger = logging.getLogger(__name__)

class EnhancedConnectionManager:
    """
    Production-grade WebSocket connection manager with role aliasing and async fixes
    """
    
    def __init__(self, session_manager):
        self.session_manager = session_manager
        self.connections: Dict[WebSocket, str] = {}
        self.logger = logging.getLogger(__name__)

    async def connect(self, websocket: WebSocket):
        """Accept and track WebSocket connection"""
        try:
            await websocket.accept()
            client_info = f"{websocket.client.host}:{websocket.client.port}"
            self.connections[websocket] = client_info
            self.logger.info(f"WebSocket connected: Address(host='{websocket.client.host}', port={websocket.client.port})")
        except Exception as e:
            self.logger.error(f"Connection error: {e}")
            raise

    async def disconnect(self, websocket: WebSocket):
        """Remove WebSocket connection from tracking"""
        try:
            client_info = self.connections.pop(websocket, "unknown")
            self.logger.info(f"WebSocket disconnected: Address(host='{websocket.client.host}', port={websocket.client.port})")
        except Exception as e:
            self.logger.error(f"Disconnect error: {e}")

    async def get_connection(self, session_id: str, role: str) -> Optional[WebSocket]:
        """
        Get WebSocket connection for a peer by role with comprehensive role aliasing
        FIXED: Maps all possible role combinations and uses proper async
        """
        try:
            # Comprehensive role aliasing to handle all role combinations
            role_mappings = {
                'receiver': ['joiner', 'receiver', 'PeerRole.JOINER'],
                'sender': ['initiator', 'sender', 'PeerRole.INITIATOR'],
                'joiner': ['joiner', 'receiver', 'PeerRole.JOINER'],
                'initiator': ['initiator', 'sender', 'PeerRole.INITIATOR']
            }
            
            # Get all possible role names to search for
            roles_to_try = role_mappings.get(role.lower(), [role.lower()])
            
            self.logger.debug(f"Looking for peer with roles: {roles_to_try} in session {session_id}")
            
            # Try each possible role name using proper async
            for role_name in roles_to_try:
                try:
                    # CRITICAL FIX: Use await instead of run_until_complete
                    peer = await self.session_manager.get_peer_by_role(session_id, role_name)
                    if peer and peer.websocket:
                        self.logger.info(f"✅ Found connection for '{role}' (matched as '{role_name}') in session {session_id}")
                        return peer.websocket
                except Exception as e:
                    self.logger.debug(f"Failed to find peer with role '{role_name}': {e}")
                    continue
            
            # If no peer found, let's debug what's actually in the session
            peers = self.session_manager.session_peers.get(session_id, {})
            peer_roles = [(pid, str(pinfo.role)) for pid, pinfo in peers.items()]
            self.logger.warning(f"No {role} found in session {session_id}")
            self.logger.debug(f"Available peers in session: {peer_roles}")
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting connection for {role}: {e}")
            return None

    def is_session_complete(self, session_id: str) -> bool:
        """Check if session has required number of participants"""
        try:
            peers = self.session_manager.session_peers.get(session_id, {})
            required_participants = 2  # Default for P2P
            
            # Get session info for dynamic participant count
            session_info = self.session_manager.sessions.get(session_id)
            if session_info and hasattr(session_info, 'max_participants'):
                required_participants = session_info.max_participants
            
            return len(peers) >= required_participants
        except Exception as e:
            self.logger.error(f"Error checking session completeness: {e}")
            return False

    def get_session_connection_count(self, session_id: str) -> int:
        """Get number of active connections in session"""
        try:
            peers = self.session_manager.session_peers.get(session_id, {})
            return len(peers)
        except Exception as e:
            self.logger.error(f"Error getting connection count: {e}")
            return 0

    def get_all_connections(self) -> Dict[WebSocket, str]:
        """Get all tracked connections"""
        return self.connections.copy()

    def get_connection_count(self) -> int:
        """Get total number of tracked connections"""
        return len(self.connections)

    async def broadcast_to_session(self, session_id: str, message: str) -> int:
        """Broadcast message to all peers in session"""
        try:
            peers = self.session_manager.session_peers.get(session_id, {})
            success_count = 0
            
            for peer_info in peers.values():
                try:
                    await peer_info.websocket.send_text(message)
                    success_count += 1
                except Exception as e:
                    self.logger.error(f"Broadcast failed to peer: {e}")
            
            return success_count
        except Exception as e:
            self.logger.error(f"Broadcast error: {e}")
            return 0
