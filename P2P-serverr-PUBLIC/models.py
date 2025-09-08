from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Set
from enum import Enum
import time

class MessageType(str, Enum):
    REGISTER = "REGISTER"
    REGISTERED = "REGISTERED"
    JOIN_SESSION = "JOIN_SESSION"
    KEY_EXCHANGE = "KEY_EXCHANGE"
    KEY_EXCHANGE_COMPLETE = "KEY_EXCHANGE_COMPLETE"
    ENCRYPTED_MESSAGE = "ENCRYPTED_MESSAGE"
    PEER_INFO = "PEER_INFO"
    RELAY = "RELAY"
    PING = "PING"
    PONG = "PONG"
    ERROR = "ERROR"
    # New token-based messages
    CREATE_INVITATION = "CREATE_INVITATION"
    INVITATION_CREATED = "INVITATION_CREATED"
    JOIN_BY_TOKEN = "JOIN_BY_TOKEN"
    JOINED_SESSION = "JOINED_SESSION"
    SESSION_READY = "SESSION_READY"
    ROLES_ASSIGNED = "ROLES_ASSIGNED"
    SESSION_TERMINATING = "SESSION_TERMINATING"
    PEER_DISCONNECTED = "PEER_DISCONNECTED"

class Role(str, Enum):
    SENDER = "sender"
    RECEIVER = "receiver"

class FileCommand(str, Enum):
    AUTH = "AUTH"
    LIST = "LIST"
    UPLOAD = "UPLOAD"
    DOWNLOAD = "DOWNLOAD"
    DELETE = "DELETE"

class SessionState(str, Enum):
    PENDING = "pending"
    NEGOTIATING = "negotiating"
    KEY_EXCHANGE = "key_exchange"
    ACTIVE = "active"
    TERMINATING = "terminating"
    EXPIRED = "expired"
    ERROR = "error"

class PeerRole(str, Enum):
    INITIATOR = "initiator"
    JOINER = "joiner"
    SENDER = "sender"
    RECEIVER = "receiver"

class ConnectionIntent(str, Enum):
    SEND_FILES = "send_files"
    RECEIVE_FILES = "receive_files"
    SHARE_FOLDER = "share_folder"
    BACKUP_DATA = "backup_data"

class ConnectionState(str, Enum):
    CONNECTING = "connecting"
    AUTHENTICATED = "authenticated"
    ESTABLISHED = "established"
    DISCONNECTING = "disconnecting"
    ERROR = "error"

# Base message class
class BaseMessage(BaseModel):
    type: MessageType
    timestamp: float = Field(default_factory=time.time)

# Authentication and Registration Messages
class RegisterMessage(BaseMessage):
    type: MessageType = MessageType.REGISTER
    role: str
    device_info: Dict[str, Any] = {}

class RegisteredMessage(BaseMessage):
    type: MessageType = MessageType.REGISTERED
    session_id: str
    role: str

class JoinSessionMessage(BaseMessage):
    type: MessageType = MessageType.JOIN_SESSION
    session_id: str
    role: str
    device_info: Dict[str, Any] = {}

# New token-based messages
class CreateInvitationMessage(BaseMessage):
    type: MessageType = MessageType.CREATE_INVITATION
    intent: ConnectionIntent = ConnectionIntent.SEND_FILES
    capabilities: List[str] = []
    expires_in_minutes: int = 30

class InvitationCreatedMessage(BaseMessage):
    type: MessageType = MessageType.INVITATION_CREATED
    token: str
    session_id: str
    expires_at: float
    share_url: str
    qr_code_data: Optional[str] = None

class JoinByTokenMessage(BaseMessage):
    type: MessageType = MessageType.JOIN_BY_TOKEN
    token: str
    intent: ConnectionIntent = ConnectionIntent.RECEIVE_FILES
    capabilities: List[str] = []

class JoinedSessionMessage(BaseMessage):
    type: MessageType = MessageType.JOINED_SESSION
    session_id: str
    role: str

class RolesAssignedMessage(BaseMessage):
    type: MessageType = MessageType.ROLES_ASSIGNED
    roles: Dict[str, str]
    session_id: str
    connection_type: str
    permissions: List[str]

# Key Exchange Messages
class KeyExchangeMessage(BaseMessage):
    type: MessageType = MessageType.KEY_EXCHANGE
    session_id: str
    public_key: str
    party: str

class KeyExchangeCompleteMessage(BaseMessage):
    type: MessageType = MessageType.KEY_EXCHANGE_COMPLETE
    session_id: str
    key_fingerprint: str
    encryption_ready: bool

# Encrypted Communication Messages
class EncryptedMessage(BaseMessage):
    type: MessageType = MessageType.ENCRYPTED_MESSAGE
    session_id: str
    target_peer: str
    encrypted_payload: str
    message_type: str

# Peer Information Messages
class PeerInfoMessage(BaseMessage):
    type: MessageType = MessageType.PEER_INFO
    session_id: str
    peer: str
    ip: str
    port: int
    ice_candidates: List[Dict] = []

class RelayMessage(BaseMessage):
    type: MessageType = MessageType.RELAY
    session_id: str
    target_peer: str
    encrypted_metadata: str

# System Messages
class PingMessage(BaseMessage):
    type: MessageType = MessageType.PING

class PongMessage(BaseMessage):
    type: MessageType = MessageType.PONG

class ErrorMessage(BaseMessage):
    type: MessageType = MessageType.ERROR
    error_code: str
    message: str

class SessionReadyMessage(BaseMessage):
    type: MessageType = MessageType.SESSION_READY
    session_id: str
    message: str

class SessionTerminatingMessage(BaseMessage):
    type: MessageType = MessageType.SESSION_TERMINATING
    session_id: str
    reason: str

class PeerDisconnectedMessage(BaseMessage):
    type: MessageType = MessageType.PEER_DISCONNECTED
    session_id: str
    peer_id: str
    reason: str
