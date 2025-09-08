Q1. What is the need of this?

The need is simple: I wanted to use my old device as a cloud server, so instead of keeping it idle, I turned it into something useful. Basically, old becomes gold.

Q2. How does the server perform work?

The working is straightforward:

A client sends a request to the WebSocket of the server.

Server link: https://p2p-server-jgqj.onrender.com/

Socket link: wss://p2p-server-jgqj.onrender.com/ws

The file connection_manager.py handles connection-making and session_manager operates management.

Testing ways:

Method 1 (Repo demo)

In the repo, there are two files:

encrypted_client.py (initiates request, gets session token)

encrypted_receiver.py (joins session with token and receives file)

First run the client → get token → paste into receiver → demo file transfers successfully.

Method 2 (Web UI)

Check my new repo: p2p-servertest-git

Live demo site: https://p2p-servertest-git.onrender.com/

Here, you can send/receive files interactively (up to 10 MB).

Works both ways (send or receive).

UI is basic (I’m not a frontend expert, got help from AI).

Q3. How safe is communication and transfer?

Security is handled properly:

The repo includes a crypto_manager.py file.

This manages end-to-end encryption for both:

Communication

Data transfer

The server only acts as a session communicator.

Actual file transfers are direct P2P → the server never sees your data.

🚀 Important Info

The repo is deploy-ready on Render, so you don’t have to waste time configuring.

I’ll be creating a repo of its desktop/mobile application in the future, which will connect directly to this server.

Open for improvements in any means — contributions, feedback, or suggestions are welcome!
