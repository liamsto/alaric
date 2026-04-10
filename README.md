# A simple remote command runner

This project is a small exploration of a secure system for running a limited set of remote commands over an end-to-end encrypted channel. Clients (i.e. the person running the command) and agents (the device the command is run on) both connect to a centralized relay server. Through that relay, the client and agent perform a Noise XX handshake. Once this is established, the server relays bytes between the two TCP streams with an end-to-end encrypted tunnel. The client and agent know little about each other besides their respective IDs.

TODO: rewrite this whole file
