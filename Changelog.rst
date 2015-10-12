TinyTLS changelog
==================


v0.9.1 alpha
-------------

NEW:
 - Tool for building calist database now allows including self-signed certificates.

FIXED:
 - Intermediate certificates with *subjectAlternativeName* extension no longer crashing the library.
 
CHANGED:
 - Class ``Binary`` moved into the ``TinyTLS`` namespace.


v0.9 alpha
------------


 - First packed release
 - TLS 1.0 implementation complete
 - Session resumption support
 - Client certificate support
 - PKCS #8 private key support
