# Text-Messaging-Application

IPTestingClient is a client program that connects to a server and can send messages to it.
IPTestingServer is a server to which multiple clients can connect. Any message sent to the server is relayed to all other clients.

The password provided to the server during setup is used as a cryptographic key.
If a client uses a different password when trying to connect to a server, its messages will not be able to be decrypted by the server, and will therefore be ignored.
If a client uses the same password when trying to connect to a server, its messages will be able to be decrypted by the server, and will be relayed to other clients.
