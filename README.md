# Discourse modifications for federated sign-in compatability with ECHOcommunity

## What it does:
 - Modifies SSO to send login requests to a remote host with a return path
 - Reads ECHOcommunity shared session cookie and performs user authentication from redis

## Changelog:

**1.8.0 - 2.3.0**
FIX: Match numbrer of arguments for impersonation method for Discourse v2

**1.8.1 - 1.8.2**
Now allows for impersonation.
Use "logout" to end impersonation and return to administrator session.