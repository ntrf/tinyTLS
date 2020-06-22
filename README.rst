=========
TinyTLS
=========

**DEPRECATED** Will be eventually replaced by `zeroTLS <https://github.com/ntrf/zerotls>`_.

TLS 1.0 client implementation designed to be small and easy to integrate


NOTICE
--------

**This project is WORK-IN-PROGRESS**. It might be not as stable and not as secure for use in production.


Requirements
--------------

In order to build tinyTLS you need:

* CMake version 3.0 or higher.
* Any C++98 compiler, but C++11 recomended.
* *optional* Node.js version 0.10 or higher.


Use cases
-----------

It's important to understand that tinyTLS does not fit every purpose.
The most important use case for this library is to provide a lightweight layer between socket api
and application level protocol, such as HTTP, for use as a web-service interface in mobile applications. 
It does not mean that tinyTLS can't be used for automated data gathering or point-to-point communications. 
However in certain use cases tinyTLS does not provide required security guarantees or is not optimized
for certain conditions. Keep that in mind when using the library.

Primary use case for library is:
 
* Both application using this library and server(s) being connected to are controlled by the same party,
* Client application connects to some limited number of servers,
* Client application might work in hostile conditions, where attacker can both listen to and apply changes
  to network traffic (such as hotel Wi-Fi or deliberate attempts at reverse engenering),
* Integrity of data trnsfered between client and server is more important than data confidentiality.

Bellow we explain some design decisions for tinyTLS.


Supported ciphers
~~~~~~~~~~~~~~~~~~~

TinyTLS tries to implement ciphers, MACs and hash algorithms that are proven to be simple, fast, popular
and secure.

Event though TLS 1.0 RFC requires implementations to support `3DES` ciphers, it's rare to see a server that
actually uses this ciphers. The reason for this is not only small security margin for `3DES`, but also 
significant performance impact as every encryption requires executing original algorithm three times.
For this reason TinyTLS follows TLS 1.1 recomendation and implements a mandatory `AES-128` cipher.

No PFS cipher suites
~~~~~~~~~~~~~~~~~~~~~~

Perfect forward secrecy (PFS) is not supported by this library as it's not as simple to implement and it 
goes beyond the advertised use case for TinyTLS. However this might change in a future versions as PFS becomes
more widespread in the internet.

Certificate validation
~~~~~~~~~~~~~~~~~~~~~~~~

TLS 1.0 RFC sets several requirements for certificate data and how it should be sent by server. However we frequently
see misconfigured servers that send multiple versions of the same certificate, certificates in wrong order, trust anchors 
and otherwise violating requirements of RFC. Instead of following those requirements pricisely, we chose to implement a
traversal algorithm, that can figure out correct order of certificates and validate a certificate chain as long as all
required certificates are present.

Certificate validation does not implement all of the required steps. TinyTLS requires certificates to be in certain format
in order to pass verification:
  
Version
    Only X.509 certificates with version 3 are supported. Older version certificates will not be parsed.
  
Issuer
    Currently TinyTLS only matches issuer field with subject field of another certificate exactly. If there is a difference
    in encoding or order of RDN fields name will not be matched. As of 2015 most CAs will only issue certificates with UTF-8
    encoding and matching issuer name so impact of this limitation should not be noticible.
  
Certificate key and signature algorithm
    TinyTLS will accept RSA certificates with at least 1024 bits keys. If any certificate in chain has lower size key - chain
    validation will fail. Currently TinyTLS supports these hash algorithms in `PKCS1-SSA-1.5` signatures: `SHA1`, `SHA-256`,
    `SHA-384`, `SHA-512`. Even though `MD5` is supported by signature verification api, it may not be used in certificate chain.
    `MD2` is not supported for signatures and never it will be.
  
Certificate contraints (extension)
    Must be present for any CA certificate in chain. Without this extension certificate is considered to be leaf certificate
    that could not be used for signing other certificates.
  
Subject alternative names (extension)
    TinyTLS uses domain name provided by client application to match it against subject alternative names list. Normaly, if this
    extension is missing, implementation is required to match the domain name against the subject common name. In TinyTLS this
    extension is required and certificate validation will fail if it's not there. However, all recently issued certificates contain
    this extension, even if certificate is issued for a single domain name.


