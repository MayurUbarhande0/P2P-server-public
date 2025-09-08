import asyncio
import sys
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import websockets
import json
import time

async def debug_broker_communication():
    """Debug step-by-step broker communication with proper message handling"""
    print("🔍 Enhanced Diagnostic Test - Message Queue Aware")
    print("=" * 60)
    
    try:
        # Connect both clients
        print("🔗 Step 1: Connecting both clients...")
        sender_ws = await websockets.connect("ws://localhost:8000/ws")
        receiver_ws = await websockets.connect("ws://localhost:8000/ws")
        print("✅ Both connected")
        
        # Step 2: Register sender
        print("\n📝 Step 2: Registering sender...")
        sender_register = {
            "type": "REGISTER",
            "role": "sender", 
            "device_info": {"debug": True},
            "timestamp": time.time()
        }
        await sender_ws.send(json.dumps(sender_register))
        
        sender_response = await sender_ws.recv()
        sender_data = json.loads(sender_response)
        print(f"📨 Sender got response: {sender_data.get('type')}")
        
        if sender_data.get("type") == "REGISTERED":
            session_id = sender_data.get("session_id")
            print(f"✅ Sender registered with session: {session_id}")
        else:
            print("❌ Sender registration failed")
            return
            
        # Step 3: Join receiver to same session
        print(f"\n🔗 Step 3: Joining receiver to session {session_id}...")
        receiver_join = {
            "type": "JOIN_SESSION",
            "session_id": session_id,
            "role": "receiver",
            "device_info": {"debug": True},
            "timestamp": time.time()
        }
        await receiver_ws.send(json.dumps(receiver_join))
        
        receiver_response = await receiver_ws.recv()
        receiver_data = json.loads(receiver_response)
        print(f"📨 Receiver got response: {receiver_data.get('type')}")
        
        if receiver_data.get("type") == "REGISTERED":
            print(f"✅ Receiver joined session: {receiver_data.get('session_id')}")
        else:
            print("❌ Receiver join failed")
            return
        
        # Step 4: Drain SESSION_READY messages from both clients
        print("\n👥 Step 4: Draining SESSION_READY messages...")
        
        # Sender might get SESSION_READY
        try:
            sender_session_msg = await asyncio.wait_for(sender_ws.recv(), timeout=2.0)
            sender_session_data = json.loads(sender_session_msg)
            print(f"📨 Sender got: {sender_session_data.get('type')}")
        except asyncio.TimeoutError:
            print("⏳ No SESSION_READY for sender (timeout)")
        
        # Receiver might get SESSION_READY
        try:
            receiver_session_msg = await asyncio.wait_for(receiver_ws.recv(), timeout=2.0)
            receiver_session_data = json.loads(receiver_session_msg)
            print(f"📨 Receiver got: {receiver_session_data.get('type')}")
        except asyncio.TimeoutError:
            print("⏳ No SESSION_READY for receiver (timeout)")
        
        # Step 5: Send public key from sender
        print("\n🔑 Step 5: Sender sending public key...")
        sender_key_msg = {
            "type": "KEY_EXCHANGE",
            "session_id": session_id,
            "public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----",
            "party": "sender",
            "timestamp": time.time()
        }
        await sender_ws.send(json.dumps(sender_key_msg))
        print("✅ Sender sent KEY_EXCHANGE message")
        
        # Step 6: Check ALL messages receiver gets
        print("\n🔍 Step 6: Checking ALL messages receiver gets...")
        messages_received = []
        
        # Collect multiple messages with timeout
        for i in range(3):  # Try to get up to 3 messages
            try:
                message = await asyncio.wait_for(receiver_ws.recv(), timeout=3.0)
                data = json.loads(message)
                msg_type = data.get('type')
                messages_received.append(msg_type)
                print(f"📨 Message {i+1}: {msg_type}")
                
                if msg_type == "PEER_PUBLIC_KEY":
                    print("🎉 SUCCESS! Receiver got PEER_PUBLIC_KEY!")
                    peer_public_key = data.get("public_key")
                    
                    # Send receiver's public key back
                    print("\n🔑 Step 7: Receiver sending public key back...")
                    receiver_key_msg = {
                        "type": "KEY_EXCHANGE",
                        "session_id": session_id,
                        "public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----",
                        "party": "receiver", 
                        "timestamp": time.time()
                    }
                    await receiver_ws.send(json.dumps(receiver_key_msg))
                    print("✅ Receiver sent KEY_EXCHANGE message")
                    
                    # Check if sender gets receiver's key
                    print("\n🔍 Step 8: Checking if sender gets PEER_PUBLIC_KEY...")
                    try:
                        sender_key_response = await asyncio.wait_for(sender_ws.recv(), timeout=5.0)
                        sender_key_data = json.loads(sender_key_response)
                        print(f"📨 Sender got: {sender_key_data.get('type')}")
                        
                        if sender_key_data.get("type") == "PEER_PUBLIC_KEY":
                            print("🎉 FULL SUCCESS! Complete key exchange working!")
                            print("✅ Broker correctly relays public keys in both directions")
                        else:
                            print(f"⚠️ Sender got: {sender_key_data.get('type')} (expected PEER_PUBLIC_KEY)")
                            
                    except asyncio.TimeoutError:
                        print("⏰ Timeout: Sender didn't receive receiver's public key")
                    break
                    
            except asyncio.TimeoutError:
                print(f"⏰ Timeout waiting for message {i+1}")
                break
        
        print(f"\n📊 Summary: Receiver got {len(messages_received)} messages: {messages_received}")
        
        if "PEER_PUBLIC_KEY" not in messages_received:
            print("❌ PEER_PUBLIC_KEY never received by receiver")
            print("🔍 This indicates the broker relay is not working")
        else:
            print("✅ PEER_PUBLIC_KEY successfully received!")
        
        # Cleanup
        await sender_ws.close()
        await receiver_ws.close()
        
    except Exception as e:
        print(f"❌ Debug test error: {e}")

if __name__ == "__main__":
    print("🚀 Running Enhanced Message Queue Debug Test")
    print("🔧 Make sure broker (app.py) is running first!")
    input("Press Enter when ready...")
    asyncio.run(debug_broker_communication())
