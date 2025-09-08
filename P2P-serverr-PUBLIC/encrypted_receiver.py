import asyncio
import sys

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import websockets
import json
import time
import base64
from typing import Dict, Any, Optional
from crypto_manager import CryptoManager
from models import *

class TokenBasedReceiver:
    def __init__(self, broker_url: str = "ws://localhost:8000/ws"):
        self.broker_url = broker_url
        self.websocket = None
        self.session_id = None
        self.crypto = CryptoManager()
        self.encryption_ready = False
        
        # File storage
        self.files = {
            "welcome.txt": base64.b64encode(b"Welcome to encrypted file sharing!").decode(),
            "readme.md": base64.b64encode(b"# Secure Storage\nYour files are encrypted!").decode(),
        }

    async def connect_to_broker(self):
        """Connect to broker server"""
        try:
            self.websocket = await websockets.connect(self.broker_url)
            print("🔗 Connected to broker as TOKEN-BASED RECEIVER")
            return True
        except Exception as e:
            print(f"❌ Failed to connect: {e}")
            return False

    async def join_by_token(self, token: str) -> bool:
        """Join session using invitation token"""
        try:
            join_msg = JoinByTokenMessage(
                token=token,
                intent=ConnectionIntent.RECEIVE_FILES,
                capabilities=["file_storage", "encryption"]
            )
            
            await self.websocket.send(join_msg.model_dump_json())
            
            # Wait for join confirmation
            response = await self.websocket.recv()
            data = json.loads(response)
            
            if data.get("type") == MessageType.JOINED_SESSION:
                self.session_id = data["session_id"]
                print(f"✅ Joined session: {self.session_id}")
                print("🎉 Connected to sender!")
                return True
            else:
                print(f"❌ Failed to join: {data.get('message', 'Unknown error')}")
                return False
                
        except Exception as e:
            print(f"❌ Join error: {e}")
            return False

    async def wait_for_key_exchange(self) -> bool:
        """Wait for and handle key exchange"""
        print("🔑 Waiting for key exchange...")
        
        try:
            while True:
                response = await self.websocket.recv()
                data = json.loads(response)
                msg_type = data.get("type")
                
                print(f"📨 Received: {msg_type}")
                
                if msg_type == "PEER_PUBLIC_KEY":
                    sender_public_key = data.get("public_key")
                    print("🔑 Received sender's public key")
                    
                    # Process sender's key and send ours
                    if self.crypto.load_peer_public_key(sender_public_key):
                        if self.crypto.derive_shared_secret():
                            fingerprint = self.crypto.get_key_fingerprint()
                            print(f"🔐 Derived shared secret! Fingerprint: {fingerprint}")
                            
                            # Send our public key
                            key_msg = KeyExchangeMessage(
                                session_id=self.session_id,
                                public_key=self.crypto.get_public_key_pem(),
                                party="receiver"
                            )
                            
                            await self.websocket.send(key_msg.model_dump_json())
                            print("🔑 Sent our public key back")
                            
                            self.encryption_ready = True
                            print("🎉 Key exchange complete - ready for encrypted commands!")
                            return True
                    
                    print("❌ Key exchange failed")
                    return False
                    
        except Exception as e:
            print(f"❌ Key exchange error: {e}")
            return False

    async def handle_encrypted_messages(self):
        """Listen for and handle encrypted commands"""
        print("\n📡 Listening for encrypted commands...")
        print("=" * 40)
        
        try:
            while True:
                response = await self.websocket.recv()
                data = json.loads(response)
                
                if data.get("type") == MessageType.ENCRYPTED_MESSAGE:
                    await self.process_encrypted_command(data)
                    
        except Exception as e:
            print(f"❌ Message handling error: {e}")

    async def process_encrypted_command(self, data: Dict[str, Any]):
        """Decrypt and process command from sender"""
        try:
            encrypted_payload = data.get("encrypted_payload")
            decrypted = self.crypto.decrypt_json(encrypted_payload)
            
            command = decrypted.get("type")
            payload = decrypted.get("payload", {})
            
            print(f"🔓 Decrypted command: {command}")
            
            # Handle different commands
            if command == "AUTH":
                await self.handle_auth(payload)
            elif command == "LIST":
                await self.handle_list_files()
            elif command == "UPLOAD":
                await self.handle_upload(payload)
            elif command == "DOWNLOAD":
                await self.handle_download(payload)
            else:
                await self.send_encrypted_response("UNKNOWN_COMMAND", f"Unknown: {command}")
                
        except Exception as e:
            print(f"❌ Command processing error: {e}")
            await self.send_encrypted_response("ERROR", "Failed to process command")

    async def handle_auth(self, payload: Dict[str, Any]):
        """Handle authentication command"""
        token = payload.get("token", "")
        user_id = payload.get("user_id", "unknown")
        
        if len(token) > 10:  # Simple validation
            print(f"✅ Authenticated user: {user_id}")
            await self.send_encrypted_response("AUTH_SUCCESS", f"Welcome {user_id}! Ready for file operations.")
        else:
            print("❌ Authentication failed")
            await self.send_encrypted_response("AUTH_FAILED", "Invalid credentials")

    async def handle_list_files(self):
        """Handle file listing command"""
        file_list = []
        for filename, file_data in self.files.items():
            file_list.append({
                "name": filename,
                "size": len(base64.b64decode(file_data)),
                "type": filename.split('.')[-1] if '.' in filename else "unknown"
            })
        
        print(f"📁 Listing {len(file_list)} files")
        await self.send_encrypted_response("FILE_LIST", f"Available files: {file_list}")

    async def handle_upload(self, payload: Dict[str, Any]):
        """Handle file upload command"""
        filename = payload.get("filename", "uploaded_file")
        file_data = payload.get("file_data", "")
        size = payload.get("size", 0)
        
        # Store the uploaded file
        self.files[filename] = file_data
        print(f"📤 Uploaded file: {filename} ({size} bytes)")
        
        await self.send_encrypted_response("UPLOAD_SUCCESS", f"File '{filename}' stored securely!")

    async def handle_download(self, payload: Dict[str, Any]):
        """Handle file download command"""
        filename = payload.get("filename", "")
        
        if filename in self.files:
            file_data = self.files[filename]
            size = len(base64.b64decode(file_data))
            print(f"📥 Sending file: {filename} ({size} bytes)")
            
            response_data = {
                "filename": filename,
                "file_data": file_data,
                "size": size
            }
            await self.send_encrypted_response("DOWNLOAD_SUCCESS", response_data)
        else:
            await self.send_encrypted_response("FILE_NOT_FOUND", f"File '{filename}' not found")

    async def send_encrypted_response(self, status: str, data: Any):
        """Send encrypted response to sender"""
        try:
            response = {
                "status": status,
                "data": data,
                "timestamp": time.time()
            }
            
            encrypted_payload = self.crypto.encrypt_json(response)
            
            encrypted_msg = EncryptedMessage(
                session_id=self.session_id,
                target_peer="sender",
                encrypted_payload=encrypted_payload,
                message_type="RESPONSE"
            )
            
            await self.websocket.send(encrypted_msg.model_dump_json())
            print(f"🔒 Sent encrypted response: {status}")
            
        except Exception as e:
            print(f"❌ Failed to send response: {e}")

    async def disconnect(self):
        """Clean disconnect"""
        if self.websocket:
            await self.websocket.close()
        if self.crypto:
            self.crypto.destroy_session()
        print("🔌 Disconnected and cleaned up")

async def main():
    print("🚀 Token-Based Encrypted File Receiver")
    print("=" * 50)
    
    # Get token from user
    token = input("📋 Enter the invitation token from sender: ").strip()
    
    if not token:
        print("❌ Token required!")
        return
    
    receiver = TokenBasedReceiver()
    
    try:
        if await receiver.connect_to_broker():
            if await receiver.join_by_token(token):
                if await receiver.wait_for_key_exchange():
                    print("\n🎉 Successfully connected and encrypted!")
                    print("📡 Ready to handle file commands...")
                    await receiver.handle_encrypted_messages()
    
    except KeyboardInterrupt:
        print("\n🛑 Session ended by user")
    except Exception as e:
        print(f"❌ Session error: {e}")
    finally:
        await receiver.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
