import asyncio
import sys

# Fix Windows asyncio connection issues
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import websockets
import json
import time
from typing import Dict, Any
from crypto_manager import CryptoManager
from models import *

class SimpleReceiver:
    def __init__(self):
        self.websocket = None
        self.session_id = None
        self.crypto = CryptoManager()
        self.encryption_ready = False
        self.waiting_for_sender = True

    async def connect_and_run(self):
        """Connect to broker and handle messages"""
        try:
            self.websocket = await websockets.connect("ws://localhost:8000/ws")
            print("🔗 Connected to broker as RECEIVER")
            
            # WAIT for sender to create session first
            print("⏳ Waiting for sender to create session...")
            await asyncio.sleep(2)  # Give sender time to register first
            
            # Register as receiver (this creates a new session for now)
            register_msg = {
                "type": "REGISTER", 
                "role": "receiver",
                "device_info": {"client_version": "1.0.0"},
                "timestamp": time.time()
            }
            
            await self.websocket.send(json.dumps(register_msg))
            print("📝 Sent registration")
            
            # Listen for messages
            while True:
                response = await self.websocket.recv()
                data = json.loads(response)
                await self.handle_message(data)
                
        except websockets.exceptions.ConnectionClosed:
            print("📡 Connection closed")
        except Exception as e:
            print(f"❌ Error: {e}")
        finally:
            if self.crypto:
                self.crypto.destroy_session()
            print("🔌 Cleaned up")

    async def handle_message(self, data: Dict[str, Any]):
        """Handle broker messages"""
        msg_type = data.get("type")
        print(f"📨 Received: {msg_type}")
        
        if msg_type == "REGISTERED":
            self.session_id = data.get("session_id")
            print(f"✅ Registered with session: {self.session_id}")
            
        elif msg_type == "PEER_PUBLIC_KEY":
            peer_public_key = data.get("public_key")
            print("🔑 Got peer's public key, starting key exchange...")
            
            # Send our public key back
            key_msg = {
                "type": "KEY_EXCHANGE",
                "session_id": self.session_id,
                "public_key": self.crypto.get_public_key_pem(),
                "party": "receiver",
                "timestamp": time.time()
            }
            await self.websocket.send(json.dumps(key_msg))
            print("🔑 Sent our public key")
            
            # Derive shared secret
            if self.crypto.load_peer_public_key(peer_public_key):
                if self.crypto.derive_shared_secret():
                    self.encryption_ready = True
                    fingerprint = self.crypto.get_key_fingerprint()
                    print(f"🔐 Encryption ready! Fingerprint: {fingerprint}")
                    self.waiting_for_sender = False
                    
        elif msg_type == "SESSION_READY":
            print("👥 Both parties connected - session ready!")
            
        elif msg_type == "ENCRYPTED_MESSAGE":
            if self.encryption_ready:
                try:
                    encrypted_payload = data.get("encrypted_payload")
                    decrypted = self.crypto.decrypt_json(encrypted_payload)
                    command = decrypted.get("type") or decrypted.get("payload", {}).get("command", "unknown")
                    print(f"🔓 Decrypted {command}: {decrypted}")
                    
                    # Send response
                    await self.send_response(decrypted)
                    
                except Exception as e:
                    print(f"❌ Decryption error: {e}")

    async def send_response(self, received_msg: Dict[str, Any]):
        """Send appropriate response based on received command"""
        try:
            command = received_msg.get("payload", {}).get("command")
            
            if command == "AUTH":
                response = {
                    "type": "RESPONSE",
                    "payload": {
                        "status": "authenticated", 
                        "message": "Welcome to encrypted storage!",
                        "command": "AUTH"
                    }
                }
            elif command == "LIST":
                response = {
                    "type": "RESPONSE", 
                    "payload": {
                        "status": "success",
                        "files": ["document.pdf", "image.jpg", "video.mp4"],
                        "command": "LIST"
                    }
                }
            elif command == "UPLOAD":
                filename = received_msg.get("payload", {}).get("filename", "unknown")
                response = {
                    "type": "RESPONSE",
                    "payload": {
                        "status": "uploaded",
                        "message": f"File '{filename}' uploaded successfully!",
                        "command": "UPLOAD"
                    }
                }
            else:
                response = {
                    "type": "RESPONSE",
                    "payload": {
                        "status": "unknown_command",
                        "message": f"Unknown command: {command}",
                        "command": command
                    }
                }
            
            # Encrypt and send response
            encrypted_payload = self.crypto.encrypt_json(response)
            
            response_msg = {
                "type": "ENCRYPTED_MESSAGE",
                "session_id": self.session_id,
                "target_peer": "sender",
                "encrypted_payload": encrypted_payload,
                "message_type": "RESPONSE",
                "timestamp": time.time()
            }
            
            await self.websocket.send(json.dumps(response_msg))
            print(f"🔒 Sent encrypted response for {command}")
            
        except Exception as e:
            print(f"❌ Response error: {e}")

async def main():
    receiver = SimpleReceiver()
    await receiver.connect_and_run()

if __name__ == "__main__":
    print("🎯 Starting Simple Receiver...")
    print("💡 Make sure to start SENDER first, then receiver!")
    asyncio.run(main())
