# trusty - the Zero Trust API

REST Synchronous & Asynchronous API + Zero Trust Synchronous & Asynchronous API.

Session hijacking prevention is now completed with an optional configuration change. This was for the very, very unlikely chance an attacker gets the dynamic session id and locks you out of that session.. Forcing you to create a new session while the other remains active. Most of the Zero Trust part of the API Server is that <i>in theory</i> the attacks that are prevented <i>could</i> be done without the prevention strategies. This specific new feature adds a lot of more advanced overhead code for the client and that is why it is optional.

<strong>Still in development / untested.<br>Synchronous API as Zero Trust and REST should be complete, however, they are untested. You may have to fix some things to get it working in the meantime. Currently working on the response server for the Asynchronous responses.</strong>

Documentation still to come!
