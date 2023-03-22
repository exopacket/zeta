# ZETA - the Zero Trust API

REST Synchronous & Asynchronous + Zero Trust Synchronous & Asynchronous API Server.<br><br>

Session hijacking prevention is now completed with an optional configuration change. This was for the very, very unlikely chance an attacker gets the dynamic session id and locks you out of that session.. Forcing you to create a new session while the other remains active. Most of the Zero Trust part of the API Server is that <i>in theory</i> the attacks that are prevented <i>could</i> be done without the prevention strategies. This specific new feature adds a lot of more advanced overhead code for the client and that is why it is optional.

# security features
  - usual validation of input with more advanced checks and flags for minor differences
  - identification through the use of an API key (the root user account), client (the device / browser), user ID (the logged in user, if used), and the unique session that all three create.
  - dynamic session authorization which gets hashed between each trip of the connection to verify that the session identification is not being used on another system.
  - dynamic API secret key to prevent session hijacking where you get locked out, create a new session, and the old one remains on another (attacker's) system.
  - asynchronous response with separate response server and removable API resources (paths)
  - dynamic request authorization for asynchronous responses
  - two way public key cryptography with two public keys and two private keys spread across the two devices (server & client). To get the full key pair both the server and client must be compromised.
