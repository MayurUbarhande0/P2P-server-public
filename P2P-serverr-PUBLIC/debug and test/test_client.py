import asyncio
import websockets
import json
import uuid

class TestClient:
    def __init__(self, broker_url: str, role: str):
        self.broker_url = broker_url
        self.role = role
        self.websocket = None
        self.session_id = None
    
    async def connect(self):
        """Connect to broker"""
        self.websocket = await websockets.connect(self.broker_url)
        print(f"Connected to broker as {self.role}")
    
    async def register(self):
        """Register with broker"""
        message = {
            "type": "REGISTER",
            "role": self.role,
            "device_info": {"device_id": str(uuid.uuid4())}
        }
        await self.websocket.send(json.dumps(message))
        
        # Wait for response
        response = await self.websocket.recv()
        data = json.loads(response)
        
        if data.get("type") == "REGISTERED":
            self.session_id = data.get("session_id")
            print(f"Registered with session ID: {self.session_id}")
            return True
        else:
            print(f"Registration failed: {data}")
            return False
    
    async def exchange_key(self, public_key: str):
        """Exchange public key"""
        message = {
            "type": "KEY_EXCHANGE",
            "session_id": self.session_id,
            "public_key": public_key,
            "party": self.role
        }
        await self.websocket.send(json.dumps(message))
        print(f"Sent public key: {public_key[:20]}...")
    
    async def send_peer_info(self, ip: str, port: int):
        """Send peer connection info"""
        message = {
            "type": "PEER_INFO",
            "session_id": self.session_id,
            "peer": self.role,
            "ip": ip,
            "port": port
        }
        await self.websocket.send(json.dumps(message))
        print(f"Sent peer info: {ip}:{port}")
    
    async def listen(self):
        """Listen for messages"""
        try:
            while True:
                message = await self.websocket.recv()
                data = json.loads(message)
                print(f"Received: {data}")
        except websockets.exceptions.ConnectionClosed:
            print("Connection closed")

async def test_sender():
    """Test sender client"""
    client = TestClient("ws://localhost:8000/ws", "sender")
    await client.connect()
    
    if await client.register():
        # Simulate key exchange
        await client.exchange_key("sender_public_key_12345")
        
        # Send peer info
        await client.send_peer_info("192.168.1.100", 9001)
        
        # Listen for messages
        await client.listen()

async def test_receiver():
    """Test receiver client"""
    client = TestClient("ws://localhost:8000/ws", "receiver")
    await client.connect()
    
    if await client.register():
        # Simulate key exchange
        await client.exchange_key("receiver_public_key_67890")
        
        # Send peer info
        await client.send_peer_info("192.168.1.101", 9002)
        
        # Listen for messages
        await client.listen()

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python test_client.py [sender|receiver]")
        sys.exit(1)
    
    role = sys.argv[1]
    if role == "sender":
        asyncio.run(test_sender())
    elif role == "receiver":
        asyncio.run(test_receiver())
    else:
        print("Role must be 'sender' or 'receiver'")
