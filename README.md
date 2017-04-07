# Discourse modifications for federated sign-in compatability with ECHOcommunity

## What it does:
 - Modifies SSO to send login requests to a remote host with a return path
 - Reads ECHOcommunity shared session cookie and performs user authentication from redis