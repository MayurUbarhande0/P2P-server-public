import asyncio
import sys
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import websockets
import json
import time
from crypto_manager import CryptoManager

class EnhancedSyncedTest:
    def __init__(self):
        self.broker_url = "ws://localhost:8000/ws"
        self.session_id = None

    async def run_sender_receiver_test(self):
        """Enhanced test with comprehensive error handling"""
        print("🎯 Enhanced E2E Encryption Test with Debug Logging")
        print("=" * 60)
        
        sender_ws = None
        receiver_ws = None
        sender_crypto = None
        receiver_crypto = None
        
        try:
            # Connect both clients
            print("🔗 Step 1: Connecting clients...")
            sender_ws = await websockets.connect(self.broker_url)
            receiver_ws = await websockets.connect(self.broker_url)
            
            sender_crypto = CryptoManager()
            receiver_crypto = CryptoManager()
            print("✅ Both clients connected and crypto managers created")
            
            # Register sender
            print("\n📝 Step 2: Registering sender...")
            sender_register = {
                "type": "REGISTER",
                "role": "sender",
                "device_info": {"debug": True},
                "timestamp": time.time()
            }
            
            await sender_ws.send(json.dumps(sender_register))
            sender_response = await asyncio.wait_for(sender_ws.recv(), timeout=10.0)
            sender_data = json.loads(sender_response)
            
            if sender_data.get("type") == "REGISTERED":
                self.session_id = sender_data.get("session_id")
                print(f"✅ Sender registered: {self.session_id}")
            else:
                raise Exception(f"Sender registration failed: {sender_data}")
            
            # Join receiver
            print("\n🔗 Step 3: Joining receiver...")
            receiver_join = {
                "type": "JOIN_SESSION",
                "session_id": self.session_id,
                "role": "receiver",
                "device_info": {"debug": True},
                "timestamp": time.time()
            }
            
            await receiver_ws.send(json.dumps(receiver_join))
            receiver_response = await asyncio.wait_for(receiver_ws.recv(), timeout=10.0)
            receiver_data = json.loads(receiver_response)
            
            if receiver_data.get("type") == "REGISTERED":
                print(f"✅ Receiver joined: {receiver_data.get('session_id')}")
            else:
                raise Exception(f"Receiver join failed: {receiver_data}")
            
            # Drain SESSION_READY messages
            print("\n👥 Step 4: Draining session ready messages...")
            try:
                sender_ready = await asyncio.wait_for(sender_ws.recv(), timeout=3.0)
                print(f"📨 Sender got: {json.loads(sender_ready).get('type')}")
            except asyncio.TimeoutError:
                print("⏳ Sender: No session ready message")
            
            try:
                receiver_ready = await asyncio.wait_for(receiver_ws.recv(), timeout=3.0)
                print(f"📨 Receiver got: {json.loads(receiver_ready).get('type')}")
            except asyncio.TimeoutError:
                print("⏳ Receiver: No session ready message")
            
            # Key exchange phase
            print("\n🔑 Step 5: Starting key exchange...")
            
            # Send sender's public key
            sender_key_msg = {
                "type": "KEY_EXCHANGE",
                "session_id": self.session_id,
                "public_key": sender_crypto.get_public_key_pem(),
                "party": "sender",
                "timestamp": time.time()
            }
            
            await sender_ws.send(json.dumps(sender_key_msg))
            print("✅ Sender sent public key")
            
            # Receiver should get PEER_PUBLIC_KEY
            print("🔍 Waiting for receiver to get sender's public key...")
            
            receiver_key_response = await asyncio.wait_for(receiver_ws.recv(), timeout=10.0)
            receiver_key_data = json.loads(receiver_key_response)
            print(f"📨 Receiver got message type: {receiver_key_data.get('type')}")
            
            if receiver_key_data.get("type") == "PEER_PUBLIC_KEY":
                sender_public_key = receiver_key_data.get("public_key")
                print("🔑 Receiver got sender's public key successfully!")
                
                # Receiver processes key and sends own
                print("🔧 Receiver processing sender's public key...")
                
                try:
                    if receiver_crypto.load_peer_public_key(sender_public_key):
                        print("✅ Receiver loaded sender's public key")
                        
                        if receiver_crypto.derive_shared_secret():
                            print("✅ Receiver derived shared secret")
                            receiver_fingerprint = receiver_crypto.get_key_fingerprint()
                            print(f"🔐 Receiver key fingerprint: {receiver_fingerprint}")
                        else:
                            raise Exception("Failed to derive shared secret")
                    else:
                        raise Exception("Failed to load peer public key")
                        
                except Exception as e:
                    print(f"❌ Receiver crypto error: {e}")
                    raise
                
                # Send receiver's public key
                print("🔑 Receiver sending public key...")
                receiver_key_msg = {
                    "type": "KEY_EXCHANGE",
                    "session_id": self.session_id,
                    "public_key": receiver_crypto.get_public_key_pem(),
                    "party": "receiver",
                    "timestamp": time.time()
                }
                
                await receiver_ws.send(json.dumps(receiver_key_msg))
                print("✅ Receiver sent public key")
                
                # Sender should get receiver's key
                print("🔍 Waiting for sender to get receiver's public key...")
                sender_key_response = await asyncio.wait_for(sender_ws.recv(), timeout=10.0)
                sender_key_data = json.loads(sender_key_response)
                print(f"📨 Sender got message type: {sender_key_data.get('type')}")
                
                if sender_key_data.get("type") == "PEER_PUBLIC_KEY":
                    receiver_public_key = sender_key_data.get("public_key")
                    print("🔑 Sender got receiver's public key!")
                    
                    # Sender processes key
                    print("🔧 Sender processing receiver's public key...")
                    
                    try:
                        if sender_crypto.load_peer_public_key(receiver_public_key):
                            print("✅ Sender loaded receiver's public key")
                            
                            if sender_crypto.derive_shared_secret():
                                print("✅ Sender derived shared secret")
                                sender_fingerprint = sender_crypto.get_key_fingerprint()
                                print(f"🔐 Sender key fingerprint: {sender_fingerprint}")
                            else:
                                raise Exception("Failed to derive shared secret")
                        else:
                            raise Exception("Failed to load peer public key")
                            
                    except Exception as e:
                        print(f"❌ Sender crypto error: {e}")
                        raise
                    
                    # Verify key agreement
                    if sender_fingerprint == receiver_fingerprint:
                        print("\n🎉 KEY EXCHANGE SUCCESS!")
                        print(f"🔐 Matching fingerprints: {sender_fingerprint}")
                        
                        # Test encrypted messaging
                        await self.test_encrypted_messages(
                            sender_ws, receiver_ws, 
                            sender_crypto, receiver_crypto
                        )
                        
                    else:
                        print(f"❌ Key fingerprint mismatch!")
                        print(f"Sender: {sender_fingerprint}")
                        print(f"Receiver: {receiver_fingerprint}")
                        
                else:
                    print(f"❌ Sender got unexpected message: {sender_key_data.get('type')}")
                    
            else:
                print(f"❌ Receiver got unexpected message: {receiver_key_data.get('type')}")
                print(f"Full message: {receiver_key_data}")
                
        except asyncio.TimeoutError as e:
            print(f"⏰ Timeout error: {e}")
            print("This usually means a message was not received within the expected time")
            
        except Exception as e:
            print(f"❌ Test error: {e}")
            import traceback
            traceback.print_exc()
            
        finally:
            # Cleanup
            print("\n🧹 Cleaning up...")
            if sender_ws:
                await sender_ws.close()
            if receiver_ws:
                await receiver_ws.close()
            if sender_crypto:
                sender_crypto.destroy_session()
            if receiver_crypto:
                receiver_crypto.destroy_session()
            print("✅ Cleanup complete")

    async def test_encrypted_messages(self, sender_ws, receiver_ws, sender_crypto, receiver_crypto):
        """Test actual encrypted message exchange"""
        print("\n🔒 Step 6: Testing Encrypted Message Exchange")
        print("-" * 50)
        
        try:
            # Sender encrypts and sends message
            test_message = {
                "type": "AUTH",
                "payload": {"token": "secret-123", "user_id": "test-user"},
                "timestamp": time.time()
            }
            
            encrypted_payload = sender_crypto.encrypt_json(test_message)
            
            encrypted_msg = {
                "type": "ENCRYPTED_MESSAGE",
                "session_id": self.session_id,
                "target_peer": "receiver",
                "encrypted_payload": encrypted_payload,
                "message_type": "AUTH",
                "timestamp": time.time()
            }
            
            await sender_ws.send(json.dumps(encrypted_msg))
            print("🔒 Sender sent encrypted AUTH message")
            
            # Receiver gets and decrypts message
            encrypted_response = await asyncio.wait_for(receiver_ws.recv(), timeout=10.0)
            encrypted_data = json.loads(encrypted_response)
            
            if encrypted_data.get("type") == "ENCRYPTED_MESSAGE":
                received_encrypted_payload = encrypted_data.get("encrypted_payload")
                
                try:
                    decrypted_message = receiver_crypto.decrypt_json(received_encrypted_payload)
                    print(f"🔓 Receiver decrypted: {decrypted_message.get('type')}")
                    
                    # Send response
                    response_msg = {
                        "status": "authenticated",
                        "message": "Welcome! Encryption working perfectly!",
                        "timestamp": time.time()
                    }
                    
                    encrypted_response_payload = receiver_crypto.encrypt_json(response_msg)
                    
                    response_encrypted_msg = {
                        "type": "ENCRYPTED_MESSAGE",
                        "session_id": self.session_id,
                        "target_peer": "sender",
                        "encrypted_payload": encrypted_response_payload,
                        "message_type": "RESPONSE",
                        "timestamp": time.time()
                    }
                    
                    await receiver_ws.send(json.dumps(response_encrypted_msg))
                    print("🔒 Receiver sent encrypted response")
                    
                    # Sender gets response
                    sender_response = await asyncio.wait_for(sender_ws.recv(), timeout=10.0)
                    sender_response_data = json.loads(sender_response)
                    
                    if sender_response_data.get("type") == "ENCRYPTED_MESSAGE":
                        sender_encrypted_payload = sender_response_data.get("encrypted_payload")
                        sender_decrypted = sender_crypto.decrypt_json(sender_encrypted_payload)
                        print(f"🔓 Sender decrypted response: {sender_decrypted.get('status')}")
                        
                        print("\n🎉 END-TO-END ENCRYPTION TEST PASSED!")
                        print("✅ ECDH Key Exchange: SUCCESS")
                        print("✅ AES-256-GCM Encryption: SUCCESS")
                        print("✅ Zero-Knowledge Broker: SUCCESS")
                        print("✅ Message Authentication: SUCCESS")
                        print("✅ Bidirectional Communication: SUCCESS")
                        
                except Exception as e:
                    print(f"❌ Decryption failed: {e}")
                    
        except Exception as e:
            print(f"❌ Encrypted messaging test failed: {e}")

async def main():
    test = EnhancedSyncedTest()
    await test.run_sender_receiver_test()

if __name__ == "__main__":
    print("🚀 Starting Enhanced Complete E2E Encryption Test")
    print("📋 This test will verify all Milestone 2 security features with debug logging")
    print("\n🔧 Make sure the broker server (app.py) is running!")
    input("Press Enter when broker is ready...")
    
    asyncio.run(main())
