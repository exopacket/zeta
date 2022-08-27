# trusty - the Zero Trust API

REST Synchronous & Asynchronous + Zero Trust Synchronous & Asynchronous API Server.<br><br>
trusty make's sure everything is set and was built with the browser in mind.<br><br>

Session hijacking prevention is now completed with an optional configuration change. This was for the very, very unlikely chance an attacker gets the dynamic session id and locks you out of that session.. Forcing you to create a new session while the other remains active. Most of the Zero Trust part of the API Server is that <i>in theory</i> the attacks that are prevented <i>could</i> be done without the prevention strategies. This specific new feature adds a lot of more advanced overhead code for the client and that is why it is optional.

<strong>Still in development / untested.<br>I have wrote a lot of code on this recently.. will be tested soon and if they're are any major problems I'll fix them, of course.</strong>

Documentation still to come!
