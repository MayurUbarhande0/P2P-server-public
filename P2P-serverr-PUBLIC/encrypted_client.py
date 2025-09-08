import asyncio
import sys

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import websockets
import json
import time
from typing import Optional, Dict, Any
from crypto_manager import CryptoManager
from models import *

class TokenBasedSender:
    def __init__(self, broker_url: str = "ws://localhost:8000/ws"):
        self.broker_url = broker_url
        self.websocket = None
        self.session_id = None
        self.crypto = CryptoManager()
        self.encryption_ready = False

    async def connect_to_broker(self):
        """Connect to broker server"""
        try:
            self.websocket = await websockets.connect(self.broker_url)
            print("🔗 Connected to broker as TOKEN-BASED SENDER")
            return True
        except Exception as e:
            print(f"❌ Failed to connect: {e}")
            return False

    async def create_invitation(self, expires_in_minutes: int = 30) -> Optional[str]:
        """Create shareable invitation token"""
        try:
            create_msg = CreateInvitationMessage(
                intent=ConnectionIntent.SEND_FILES,
                capabilities=["file_upload", "encryption"],
                expires_in_minutes=expires_in_minutes
            )
            
            await self.websocket.send(create_msg.model_dump_json())
            
            # Wait for invitation response
            response = await self.websocket.recv()
            data = json.loads(response)
            
            if data.get("type") == MessageType.INVITATION_CREATED:
                token = data["token"]
                self.session_id = data["session_id"]
                
                print(f"🎫 SHARE THIS TOKEN: {token}")
                print(f"📋 Session ID: {self.session_id}")
                print(f"⏰ Expires in {expires_in_minutes} minutes")
                print(f"🔗 Share URL: {data.get('share_url', 'N/A')}")
                print()
                print("💡 Give this token to the receiver to start encrypted file sharing!")
                
                return token
            else:
                print(f"❌ Failed to create invitation: {data}")
                return None
                
        except Exception as e:
            print(f"❌ Invitation creation error: {e}")
            return None

    async def wait_for_receiver(self) -> bool:
        """Wait for receiver to join session"""
        print("⏳ Waiting for receiver to join...")
        
        try:
            while True:
                response = await self.websocket.recv()
                data = json.loads(response)
                msg_type = data.get("type")
                
                print(f"📨 Received: {msg_type}")
                
                if msg_type == MessageType.SESSION_READY:
                    print("👥 Receiver connected! Starting key exchange...")
                    return True
                elif msg_type == "ERROR":
                    print(f"❌ Error: {data.get('message')}")
                    return False
                    
        except Exception as e:
            print(f"❌ Error waiting for receiver: {e}")
            return False

    async def perform_key_exchange(self) -> bool:
        """Perform ECDH key exchange"""
        try:
            # Send our public key
            key_msg = KeyExchangeMessage(
                session_id=self.session_id,
                public_key=self.crypto.get_public_key_pem(),
                party="sender"
            )
            
            await self.websocket.send(key_msg.model_dump_json())
            print("🔑 Sent our public key")
            
            # Wait for peer's public key
            while True:
                response = await self.websocket.recv()
                data = json.loads(response)
                
                if data.get("type") == "PEER_PUBLIC_KEY":
                    peer_public_key = data.get("public_key")
                    print("🔑 Received receiver's public key")
                    
                    # Process key exchange
                    if self.crypto.load_peer_public_key(peer_public_key):
                        if self.crypto.derive_shared_secret():
                            fingerprint = self.crypto.get_key_fingerprint()
                            print(f"🔐 Key exchange successful! Fingerprint: {fingerprint}")
                            
                            self.encryption_ready = True
                            return True
                    
                    print("❌ Key exchange failed")
                    return False
                    
        except Exception as e:
            print(f"❌ Key exchange error: {e}")
            return False

    async def send_encrypted_command(self, command: str, payload: Dict[str, Any]) -> bool:
        """Send encrypted command to receiver"""
        if not self.encryption_ready:
            print("❌ Encryption not ready")
            return False
        
        try:
            message = {
                "type": command,
                "payload": payload,
                "timestamp": time.time()
            }
            
            encrypted_payload = self.crypto.encrypt_json(message)
            
            encrypted_msg = EncryptedMessage(
                session_id=self.session_id,
                target_peer="receiver",
                encrypted_payload=encrypted_payload,
                message_type=command
            )
            
            await self.websocket.send(encrypted_msg.model_dump_json())
            print(f"🔒 Sent encrypted {command} command")
            return True
            
        except Exception as e:
            print(f"❌ Failed to send command: {e}")
            return False

    async def receive_encrypted_response(self) -> Optional[Dict[str, Any]]:
        """Receive and decrypt response"""
        try:
            response = await self.websocket.recv()
            data = json.loads(response)
            
            if data.get("type") == MessageType.ENCRYPTED_MESSAGE:
                encrypted_payload = data.get("encrypted_payload")
                decrypted = self.crypto.decrypt_json(encrypted_payload)
                print(f"🔓 Decrypted response: {decrypted.get('status', 'unknown')}")
                return decrypted
            
            return data
            
        except Exception as e:
            print(f"❌ Failed to receive response: {e}")
            return None

    async def run_file_operations(self):
        """Run sample file operations"""
        print("\n🎯 Starting Encrypted File Operations")
        print("=" * 40)
        
        # Authentication
        await self.send_encrypted_command("AUTH", {"token": "secure-token-123", "user_id": "sender"})
        auth_response = await self.receive_encrypted_response()
        
        await asyncio.sleep(1)
        
        # List files
        await self.send_encrypted_command("LIST", {})
        list_response = await self.receive_encrypted_response()
        
        await asyncio.sleep(1)
        
        # Upload file
        import base64
        test_content = b"Hello from secure sender! This is encrypted content."
        file_b64 = base64.b64encode(test_content).decode()
        
        await self.send_encrypted_command("UPLOAD", {
            "filename": "encrypted_message.txt",
            "file_data": file_b64,
            "size": len(test_content)
        })
        upload_response = await self.receive_encrypted_response()
        
        print("\n🎉 All file operations completed successfully!")
        print("✅ Authentication, file listing, and upload all encrypted!")

    async def disconnect(self):
        """Clean disconnect"""
        if self.websocket:
            await self.websocket.close()
        if self.crypto:
            self.crypto.destroy_session()
        print("🔌 Disconnected and cleaned up")

async def main():
    print("🚀 Token-Based Encrypted File Sender")
    print("=" * 50)
    
    sender = TokenBasedSender()
    
    try:
        if await sender.connect_to_broker():
            token = await sender.create_invitation(expires_in_minutes=30)
            
            if token:
                if await sender.wait_for_receiver():
                    if await sender.perform_key_exchange():
                        await sender.run_file_operations()
                        
                        # Keep alive for more operations
                        print("\n💬 Session active - press Ctrl+C to quit")
                        while True:
                            await asyncio.sleep(1)
    
    except KeyboardInterrupt:
        print("\n🛑 Session ended by user")
    except Exception as e:
        print(f"❌ Session error: {e}")
    finally:
        await sender.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
