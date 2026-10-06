---
title: "PQ/T Hybrid Composite Signatures for JOSE and COSE"
abbrev: "JOSE/COSE Composite Signatures"
category: std

docname: draft-ietf-jose-pq-composite-sigs-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Javascript Object Signing and Encryption"
keyword:
 - JOSE
 - COSE
 - PQC
 - ML-DSA
 - Signature
 - Hybrid
venue:
  group: "Javascript Object Signing and Encryption"
  type: "Working Group"
  mail: "jose@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/jose/"
  github: "ietf-wg-jose/draft-ietf-jose-pq-composite-sigs"
  latest: "https://ietf-wg-jose.github.io/draft-ietf-jose-pq-composite-sigs/draft-ietf-jose-pq-composite-sigs.html"

author:
  - ins: L. Prabel
    fullname: Lucas Prabel
    organization: Huawei
    email: "lucas.prabel@huawei.com"
  - ins: S. Sun
    fullname: Sun Shuzhou
    organization: Huawei
    email: "sunshuzhou@huawei.com"
  - ins: J. Gray
    fullname: John Gray
    organization: Entrust Limited
    abbrev: Entrust
    email: "john.gray@entrust.com"
  - ins: T. Reddy
    fullname: Tirumaleswar Reddy
    organization: Nokia
    city: Bangalore
    region: Karnataka
    country: India
    email: "kondtir@gmail.com"

normative:
  RFC6090:
  RFC8032:
  RFC7515:
  RFC7517:
  RFC7518:
  RFC7638:
  RFC9679:
  RFC3279:
  RFC5915:
  RFC9052:
  RFC9964:
  I-D.draft-ietf-lamps-pq-composite-sigs: COMPOSITE-LAMPS
  IANA.JOSE:
    title: "JSON Object Signing and Encryption (JOSE)"
    date: ~
    author:
      org: IANA
    target: https://www.iana.org/assignments/jose/jose.xhtml
  IANA.COSE:
    title: "CBOR Object Signing and Encryption (COSE)"
    date: ~
    author:
      org: IANA
    target: https://www.iana.org/assignments/cose/cose.xhtml
  FIPS.204:
    title: "Module-Lattice-Based Digital Signature Standard"
    date: August 2024
    author:
      org: "National Institute of Standards and Technology (NIST)"
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
  X9.62-2005:
    title: "Public Key Cryptography for the Financial Services Industry: the Elliptic Curve Digital Signature Algorithm (ECDSA)"
    date: 2005-11
    author:
      org: "American National Standards Institute"
    seriesinfo:
      ANSI: X9.62-2005

informative:
  RFC9053:
  RFC9054:
  RFC7519:
  RFC8392:
  RFC9360:
  RFC9794:
  I-D.draft-ietf-pquip-hybrid-signature-spectrums: HYB-SIG-SPECTRUMS
---

--- abstract

This document describes JSON Object Signing and Encryption (JOSE) and CBOR Object Signing and Encryption (COSE) serializations for PQ/T hybrid composite signatures. The composite algorithms described combine ML-DSA as the post-quantum component and either ECDSA or EdDSA as the traditional component.

--- middle

# Introduction

The impact of a potential Cryptographically Relevant Quantum Computer (CRQC) on algorithms whose security is based on mathematical problems such as integer factorisation or discrete logarithms over finite fields or elliptic curves raises the need for new algorithms that are perceived to be secure against CRQC as well as classical computers. Such algorithms are called post-quantum, while algorithms based on integer factorisation or discrete logarithms are called traditional.

While switching from a traditional algorithm to a post-quantum one intends to strengthen the security against an adversary possessing a quantum computer, the lack of maturing time of post-quantum algorithms compared to traditional algorithms raises uncertainty about their security.

Thus, the joint use of a traditional algorithm and a post-quantum algorithm in protocols represents a solution to this problem by providing security as long as at least one of the traditional or post-quantum components remains secure.

This document describes JSON Object Signing and Encryption (JOSE) and CBOR Object Signing and Encryption (COSE) serializations for hybrid composite signatures. The composite algorithms described combine ML-DSA as the post-quantum component and either ECDSA or EdDSA as the traditional component.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document follows the terminology for post-quantum hybrid schemes defined in {{RFC9794}}.

This section recalls some of this terminology, but also adds other definitions used throughout the whole document:

"Asymmetric Traditional Cryptographic Algorithm":
         An asymmetric cryptographic algorithm based on integer factorisation, finite field discrete logarithms, elliptic curve discrete logarithms, or related mathematical problems. A related mathematical problem is one that can be solved by solving the integer factorisation, finite field discrete logarithm or elliptic curve discrete logarithm problem. Where there is little risk of confusion asymmetric traditional cryptographic algorithms can also be referred to as traditional algorithms for brevity.

"Post-Quantum Algorithm":
         An asymmetric cryptographic algorithm that is intended to be secure against attacks using quantum computers as well as classical computers. As with all cryptography, it always remains the case that attacks, either quantum or classical, may be found against post-quantum algorithms. Therefore it should not be assumed that just because an algorithm is designed to provide post-quantum security it will not be compromised.

"Post-Quantum Traditional (PQ/T) Hybrid Scheme":
         A multi-algorithm scheme where at least one component algorithm is a post-quantum algorithm and at least one is a traditional algorithm.

"PQ/T Hybrid Digital Signature":
         A multi-algorithm digital signature scheme made up of two or more component digital signature algorithms where at least one is a post-quantum algorithm and at least one is a traditional algorithm.

"Composite Algorithm":
          An algorithm which is a sequence of two component algorithms, as defined in {{-COMPOSITE-LAMPS}}.

"Component Algorithm":
         Each cryptographic algorithm that forms part of a cryptographic scheme.

# Algorithm Key Pair (AKP) Type {#sec-akp}

This document makes use of the Algorithm Key Pair (AKP) type which is defined in {{RFC9964}}.

As a reminder, the AKP type is used to express public and private keys for use with algorithms. The parameters for public and private keys contain byte strings.

This document makes use of the serialization routines defined in {{-COMPOSITE-LAMPS}} to obtain the byte string encodings of the composite public and private keys.

The process to compute JWK Thumbprint and COSE Key Thumbprint as described in {{RFC7638}} and {{RFC9679}} is detailed in {{RFC9964}}.

# Composite ML-DSA in JOSE and COSE

The composite algorithms registered in this document are the Composite ML-DSA algorithms defined in {{-COMPOSITE-LAMPS}}. Key generation, signature generation, signature verification, and the serialization of composite keys and signatures are performed exactly as specified in {{-COMPOSITE-LAMPS}}, and are not repeated here. In particular, composite keys and signatures are encoded using the `SerializePublicKey`, `SerializePrivateKey` and `SerializeSignatureValue` routines of {{-COMPOSITE-LAMPS}}, and decoded using the corresponding `DeserializePublicKey`, `DeserializePrivateKey` and `DeserializeSignatureValue` routines.

## Use in JOSE and COSE {#sec-use-jose-cose}

The Composite ML-DSA algorithms are used in JOSE and COSE as follows:

* Signatures are produced as described in {{Section 5.1 of RFC7515}} for JOSE and in {{Section 4 of RFC9052}} for COSE, using the Composite ML-DSA algorithm as the signature algorithm. The signature value is the output of `SerializeSignatureValue`.
* The application context string `ctx` passed to the Composite ML-DSA signature generation and verification algorithms MUST be the empty string, similarly to {{RFC9964}}. As a consequence, the context length byte in the message representative `M'` defined in {{-COMPOSITE-LAMPS}} is always 0x00.
* The prefix, as well as the label and the pre-hash algorithm of each composite algorithm, are those defined in {{-COMPOSITE-LAMPS}}. The prefix is the ASCII encoding of the string "CompositeAlgorithmSignatures2025", which in hex is 43 6F 6D 70 6F 73 69 74 65 41 6C 67 6F 72 69 74 68 6D 53 69 67 6E 61 74 75 72 65 73 32 30 32 35. The labels are recalled in {{tab-sig-alg-label}}, and the pre-hash algorithms in {{tab-jose-algs}} (for JOSE) and {{tab-cose-algs}} (for COSE).
* Composite keys are expressed using the AKP key type (see {{sec-akp}}). The `pub` parameter contains the output of `SerializePublicKey`, and the `priv` parameter contains the output of `SerializePrivateKey`. As in {{RFC9964}}, the ML-DSA component of the private key MUST be the 32-byte seed.

For the ECDSA component, the signature, private key and public key are encoded as in {{-COMPOSITE-LAMPS}}: the signature as an Ecdsa-Sig-Value {{RFC3279}}, the private key as an ECPrivateKey {{RFC5915}}, and the public key as an uncompressed X9.62 {{X9.62-2005}} point. {{sec-ecdsa-encoding}} gives guidance on how to produce and parse these encodings. For the EdDSA component, keys and signatures are encoded as defined in {{RFC8032}}.

## ECDSA Encodings {#sec-ecdsa-encoding}

This section describes how to construct and parse the three ECDSA encodings required by this document: the DER-encoded Ecdsa-Sig-Value {{RFC3279}} and ECPrivateKey {{RFC5915}} structures, and the X9.62 {{X9.62-2005}} uncompressed point encoding used for public keys. None of it requires implementers to write a general-purpose ASN.1 encoder or decoder, but implementers who already have access to a standard ASN.1/DER library MAY simply use it instead for the two DER structures.

| Field | Encoding used in this document | P-256 | P-384 |
|:---|:---|:---|:---|
| Private key | ECPrivateKey ({{sec-ecdsa-encoding-priv}}) | 51 | 64 |
| Public key | X9.62 uncompressed point ({{sec-ecdsa-encoding-pub}}) | 65 | 97 |
| Signature | Ecdsa-Sig-Value ({{sec-ecdsa-encoding-sig}}) | <= 72 | <= 104 |
{: #table-ecdsa-sizes title="Sizes (in bytes) of ECDSA keys and signatures as encoded in this document"}

### Ecdsa-Sig-Value (Signatures) {#sec-ecdsa-encoding-sig}

Ecdsa-Sig-Value is defined in {{Section 2.2.3 of RFC3279}} as:

~~~ asn.1
Ecdsa-Sig-Value ::= SEQUENCE {
    r     INTEGER,
    s     INTEGER
}
~~~

r and s are the same big-endian integer values used by {{RFC7518}} and {{RFC9053}}, where they are zero-padded to a fixed length for a given curve (32 bytes each for P-256, 48
bytes each for P-384). As integers, however, r and s can have fewer significant bytes than this fixed length whenever their leading bytes are zero; Step 1 below removes this padding before re-encoding them as DER INTEGERs. Building an Ecdsa-Sig-Value from r and s takes two steps:

- first, r and s are each turned independently into a DER INTEGER (Step 1);
- then the two results are wrapped in a DER SEQUENCE (Step 2).

Decoding reverses these two steps. No prior ASN.1 knowledge is assumed below.

**Step 1: encode r and s as DER INTEGERs.**

A DER INTEGER is written as a 0x02 tag byte, a length byte, and the value's bytes. Because a DER INTEGER is signed, an extra 0x00 byte is
prepended whenever the value would otherwise be misread as negative, i.e. whenever its first byte is 0x80 or greater.

{{table-ecdsa-sig-encode}} explains how to turn a raw value (r or s) into its DER encoding.

| First byte after removing leading 0x00 bytes (keeping at least one byte) | DER encoding |
|:---|:---|
| less than 0x80 | 0x02, then the length in bytes of the trimmed value, then the trimmed value |
| 0x80 or greater | 0x02, then the length in bytes of the trimmed value plus 1, then 0x00, then the trimmed value |
{: #table-ecdsa-sig-encode title="Turning a raw value (r or s) into its DER encoding"}

The length is always written as a single byte in this document: r, s, and their DER encodings are always well under 128 bytes, so DER's multi-byte "long form" length encoding is never needed here.

For example, for P-256 (32-byte r and s):

- if r starts with `4F ...` (no leading zero byte, and 0x4F is less than 0x80), its DER encoding is `02 20 <r, 32 bytes>` (0x20 = 32);
- if r starts with `F3 ...` (no leading zero byte, and 0xF3 is greater than 0x80), its DER encoding is `02 21 00 <r, 32 bytes>` (0x21 = 33);
- if r starts with `00 07 ...` (one leading zero byte to remove, and 0x07 is less than 0x80), its DER encoding is `02 1F <r without its leading 0x00, 31 bytes>` (0x1F = 31).

**Step 2: wrap r's and s's DER encodings in a SEQUENCE.**

Using the two encodings produced in Step 1, the full Ecdsa-Sig-Value is simply the concatenation

`Ecdsa-Sig-Value <- 0x30 || length || r's DER encoding || s's DER encoding`

where length is a single byte equal to the combined length, in bytes, of r's and s's DER encodings from Step 1, and r's encoding always
comes before s's.

Continuing the example above: taking r's DER encoding from the third case (`02 1F <31 bytes>`, 33 bytes total) and an s whose DER encoding
corresponds to the first case (`02 20 <32 bytes>`, 34 bytes total), the combined length is 33 + 34 = 67 = 0x43, and the full
Ecdsa-Sig-Value is `30 43 <r's DER encoding> <s's DER encoding>` (69 bytes total).

**Decoding** reverses Steps 2 and 1, in that order.

### ECPrivateKey (Private Keys) {#sec-ecdsa-encoding-priv}

ECPrivateKey is defined in {{RFC5915}} as:

~~~ asn.1
ECPrivateKey ::= SEQUENCE {
    version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
    privateKey     OCTET STRING,
    parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
    publicKey  [1] BIT STRING OPTIONAL
}
~~~

Given the raw, fixed-length ECDSA private key d (curve size n: 32 bytes for P-256, 48 bytes for P-384), the ECPrivateKey is d inserted between two fixed byte sequences that depend only on the curve (the publicKey field is never included):

`ECPrivateKey <- bytes before d || d || bytes after d`

The fixed byte sequences are given in {{table-ecprivatekey-build}}:

| Curve | Bytes before d | d | Bytes after d |
|:---|:---|:---|:---|
| P-256 | `30 31 02 01 01 04 20` | `<d, 32 bytes>` | `A0 0A 06 08 2A 86 48 CE 3D 03 01 07` |
| P-384 | `30 3E 02 01 01 04 30` | `<d, 48 bytes>` | `A0 07 06 05 2B 81 04 00 22` |
{: #table-ecprivatekey-build title="Construction of an ECPrivateKey, by curve"}

For example, for P-256 (n = 32), with d = `D1 D2 ...D32`:

~~~
30 31                                 SEQUENCE (length 0x31 = 49)
   02 01 01                           version (INTEGER, value 1)
   04 20 D1 D2 ... D32                private key (OCTET STRING)
   A0 0A                              parameters (A0: explicit tag 0)
      06 08 2A 86 48 CE 3D 03 01 07   OID (OBJECT IDENTIFIER, P-256)
~~~

**Decoding** reverses the same construction.

### X9.62 Uncompressed Point (Public Keys) {#sec-ecdsa-encoding-pub}

The ECDSA public key in this document is encoded as the X9.62 {{X9.62-2005}} uncompressed point:

`ECDSA public key <- 0x04 || x || y`

where x and y are the same raw, fixed-length, big-endian coordinate values already used by {{RFC7518}} and {{RFC9053}} (32 bytes
each for P-256, 48 bytes each for P-384).

# Composite Signature Instantiations

The ML-DSA signature scheme supports three possible parameter sets, each of which corresponding to a specific security strength. See {{FIPS.204}} for more considerations on that matter.

The combinations in {{tab-jose-algs}} and {{tab-cose-algs}} are a subset of those defined in {{-COMPOSITE-LAMPS}}. As explained there, each ML-DSA parameter set is paired with commonly deployed traditional algorithms, rather than with a traditional algorithm of exactly the same security level, as such an exact match is difficult to define, since there is no consensus on how to compare security against classical adversaries with security against quantum adversaries.

The {{FIPS.204}} specification defines both pure and pre-hash modes for ML-DSA, referred to as "ML-DSA" and "HashML-DSA" respectively. This document only specifies a single mode which is similar in construction to HashML-DSA. However, because the pre-hashing is done at the composite level, only the pure ML-DSA algorithm is used as the underlying ML-DSA primitive.

## JOSE algorithms

The following table defines a list of algorithms associated with specific PQ/T combinations to be registered in {{IANA.JOSE}}.

| Name | First Algorithm | Second Algorithm | Pre-Hash | Description
| ----------- | ----------- |  ----------- | ----------- | ----------- |
| ML-DSA-44-ES256 | ML-DSA-44  | ecdsa-with-SHA256 with P-256 | SHA256 | Composite Signature with ML-DSA-44 and ECDSA using P-256 curve and SHA256 |
| ML-DSA-65-ES256  | ML-DSA-65 | ecdsa-with-SHA256 with P-256 | SHA512 | Composite Signature with ML-DSA-65 and ECDSA using P-256 curve and SHA256 |
| ML-DSA-87-ES384  | ML-DSA-87 | ecdsa-with-SHA384 with P-384 | SHA512 | Composite Signature with ML-DSA-87 and ECDSA using P-384 curve and SHA384 |
| ML-DSA-44-Ed25519 | ML-DSA-44  | Ed25519 | SHA512 | Composite Signature with ML-DSA-44 and Ed25519 |
| ML-DSA-65-Ed25519 | ML-DSA-65  | Ed25519 | SHA512 | Composite Signature with ML-DSA-65 and Ed25519 |
| ML-DSA-87-Ed448   | ML-DSA-87  | Ed448   | SHAKE256 | Composite Signature with ML-DSA-87 and Ed448 |
{: #tab-jose-algs title="JOSE Composite Signature Algorithms for ML-DSA"}

Examples can be found in {{appdx-jose}}.

## COSE algorithms

The following table defines a list of algorithms associated with specific PQ/T combinations to be registered in {{IANA.COSE}}.


| Name | COSE Value | First Algorithm | Second Algorithm | Pre-Hash | Description
| ----------- | ----------- | ----------- | ----------- | ----------- | ----------- |
| ML-DSA-44-ES256           | TBD (request assignment -54) | ML-DSA-44 | ecdsa-with-SHA256 with P-256 | SHA256 | Composite Signature with ML-DSA-44 and ECDSA using P-256 curve and SHA256 |
| ML-DSA-65-ES256           | TBD (request assignment -55) | ML-DSA-65 | ecdsa-with-SHA256 with P-256 | SHA512 | Composite Signature with ML-DSA-65 and ECDSA using P-256 curve and SHA256 |
| ML-DSA-87-ES384           | TBD (request assignment -56) | ML-DSA-87 | ecdsa-with-SHA384 with P-384 | SHA512 | Composite Signature with ML-DSA-87 and ECDSA using P-384 curve and SHA384 |
| ML-DSA-44-Ed25519         | TBD (request assignment -57) | ML-DSA-44 | Ed25519 | SHA512 | Composite Signature with ML-DSA-44 and Ed25519 |
| ML-DSA-65-Ed25519         | TBD (request assignment -58) | ML-DSA-65 | Ed25519 | SHA512 | Composite Signature with ML-DSA-65 and Ed25519 |
| ML-DSA-87-Ed448           | TBD (request assignment -59) | ML-DSA-87 | Ed448   | SHAKE256 | Composite Signature with ML-DSA-87 and Ed448 |
{: #tab-cose-algs title="COSE Composite Signature Algorithms for ML-DSA"}

Examples can be found in {{appdx-cose}}.

## Composite Labels for JOSE and COSE

The JOSE and COSE composite label values are listed in {{tab-sig-alg-label}}.

They are represented here as ASCII strings, but implementers MUST convert them to byte strings using the obvious ASCII conversions prior to concatenating them with other byte values, as in {{-COMPOSITE-LAMPS}}.

| "alg" Header Parameter | Label (in ASCII) | Label (in Hex encoding) |
| ----------- | ----------- | ----------- |
| ML-DSA-44-ES256   | COMPSIG-MLDSA44-ECDSA-P256-SHA256 | 43 4F 4D 50 53 49 47 2D 4D 4C 44 53 41 34 34 2D 45 43 44 53 41 2D 50 32 35 36 2D 53 48 41 32 35 36 |
| ML-DSA-65-ES256   | COMPSIG-MLDSA65-ECDSA-P256-SHA512 | 43 4F 4D 50 53 49 47 2D 4D 4C 44 53 41 36 35 2D 45 43 44 53 41 2D 50 32 35 36 2D 53 48 41 35 31 32 |
| ML-DSA-87-ES384   | COMPSIG-MLDSA87-ECDSA-P384-SHA512 | 43 4F 4D 50 53 49 47 2D 4D 4C 44 53 41 38 37 2D 45 43 44 53 41 2D 50 33 38 34 2D 53 48 41 35 31 32 |
| ML-DSA-44-Ed25519 | COMPSIG-MLDSA44-Ed25519-SHA512    | 43 4F 4D 50 53 49 47 2D 4D 4C 44 53 41 34 34 2D 45 64 32 35 35 31 39 2D 53 48 41 35 31 32 |
| ML-DSA-65-Ed25519 | COMPSIG-MLDSA65-Ed25519-SHA512    | 43 4F 4D 50 53 49 47 2D 4D 4C 44 53 41 36 35 2D 45 64 32 35 35 31 39 2D 53 48 41 35 31 32 |
| ML-DSA-87-Ed448   | COMPSIG-MLDSA87-Ed448-SHAKE256    | 43 4F 4D 50 53 49 47 2D 4D 4C 44 53 41 38 37 2D 45 64 34 34 38 2D 53 48 41 4B 45 32 35 36 |
{: #tab-sig-alg-label title="JOSE/COSE Composite Label Values"}

# Security Considerations

The security considerations of the component algorithms (ML-DSA, ECDSA, and EdDSA) as described in {{FIPS.204}}, {{RFC6090}}, and {{RFC8032}} apply to this document.

Similarly, the security considerations relative to the JWS, JWK, AKP and COSE structures {{RFC7515}}, {{RFC7517}}, {{RFC9964}} and {{RFC9052}} apply to this document.

The security considerations of {{-COMPOSITE-LAMPS}} also apply to the composite algorithms used in this document.

In addition, the following considerations specific to the composite design and its use in JOSE/COSE must be taken into account.

## Hybrid Security and Quantum Resistance

An important objective of Composite ML-DSA is to provide protection against CRQCs. Under a CRQC, traditional signature algorithms (ECDSA, EdDSA) are vulnerable to private-key recovery, enabling attackers to forge arbitrary JWS objects or COSE_Sign/COSE_Sign1 structures and fully impersonate the signer.

By requiring the successful verification of both the ML-DSA component and the traditional component, this construction ensures:

* An adversary that compromises only one of the component algorithms cannot produce cryptographically protected JOSE/COSE objects as long as the other component remains secure. In particular, this prevents JOSE/COSE signature spoofing and impersonation attacks even if the traditional signature component is compromised.
* The scheme provides existential unforgeability under chosen-message attack (EUF-CMA) provided that at least one component algorithm is EUF-CMA secure and the pre-hash function `PH` is collision-resistant. This is the case for all combinations present in this document.

## Component Key Integrity and Reuse

The security analysis of Composite ML-DSA in {{-COMPOSITE-LAMPS}} assumes that the two component keys of a composite key are freshly generated together and are not used anywhere else. The considerations below apply to composite keys used with JOSE and COSE.

* To avoid key reuse, when generating a new composite key, the key generation functions for both component algorithms MUST be executed. Moreover, compliant parties MUST NOT use, import, or export component keys that are used in other contexts, combinations, or as standalone keys. In particular, existing key material, such as an ECDSA, EdDSA or ML-DSA key already published as a JWK or COSE_Key, MUST NOT be reused as a component of a composite key. If a component key is also used on its own, a component signature taken out of a composite signature verifies under that key as a signature over the message representative `M'`. The prefix and label leave evidence that the signature comes from a composite, but they do not prevent this. Key reuse MUST therefore be avoided despite the weak non-separability of the combiner.

* A composite public key can be conveyed in an X.509 certificate, using the `x5c` header parameter in JOSE ({{Section 4.1.6 of RFC7515}}) or the `x5chain` header parameter in COSE {{RFC9360}}. Such a certificate carries the composite key as specified in {{-COMPOSITE-LAMPS}}, with the same serialized public key as the `pub` parameter. In that case, the binding between the composite key and the signer is only as strong as the signatures on the certificates of the chain. A quantum adversary cannot forge a certificate signed with Composite ML-DSA as long as ML-DSA remains secure. If a certificate of the chain is signed with a traditional algorithm only, such an adversary can obtain a certificate for a composite key of its choice, and the composite signature on the JWS or COSE object no longer provides protection against a CRQC. The same holds for any other mechanism used to distribute composite public keys.

## Domain Separation and Non-Separability

The Composite ML-DSA signature combiner defined in {{-COMPOSITE-LAMPS}} prepends a fixed `Prefix` and an algorithm-specific `Label` to the pre-hashed message before signing.

* By binding the two component signatures to the specific composite algorithm, the composite scheme achieves "weak non-separability" as defined in {{-HYB-SIG-SPECTRUMS}}.
* The label, specific to each composite algorithm, helps protect against component signatures being removed from the composite and used in another context. However, it does not fully prevent it as the traditional component still verifies under the traditional algorithm as a signature over `M'`, which is why key reuse is forbidden.

For more information about the security properties relative to the signature combiner, the user can read {{-COMPOSITE-LAMPS}}.

## Security Objectives and Limitations

In JOSE/COSE, the security objective of digital signatures is to ensure that only an authorized signer can produce a valid signature over a given protected header and payload.

Therefore, users should be aware of specific scenarios where Composite ML-DSA may not be appropriate:

* While the construction is SUF-CMA secure against classical adversaries when paired with Ed25519 or Ed448, it is not SUF-CMA secure against quantum adversaries (who can break the traditional component). Consequently, applications for which SUF-CMA security is a strict requirement SHOULD NOT use Composite ML-DSA.
* Composite ML-DSA does not guarantee that a message has a single valid signature. Applications therefore cannot use the signature value, or a hash of the complete JWS or COSE object, as a unique identifier.
* Replay protection is not handled by the signature itself but must be addressed through claims such as `exp`, `nbf`, and `jti` in JOSE ({{Section 4.1 of RFC7519}}) or the equivalent claims in COSE ({{Section 3 of RFC8392}}).

# IANA Considerations

## JOSE Algorithms

The following values of the JWS "alg" (algorithm) are requested to be added to the "JSON Web Signature and Encryption Algorithms" registry.
They are represented following the registration template provided in {{RFC7518}}.

### ML-DSA-44-ES256

* Algorithm Name: ML-DSA-44-ES256
* Algorithm Description: Composite Signature with ML-DSA-44 and ECDSA using P-256 curve and SHA-256
* Algorithm Usage Location(s): alg
* JOSE Implementation Requirements: Optional
* Change Controller: IETF
* Specification Document(s): RFC XXXX
* Algorithm Analysis Documents(s): {{-COMPOSITE-LAMPS}}

### ML-DSA-65-ES256

* Algorithm Name: ML-DSA-65-ES256
* Algorithm Description: Composite Signature with ML-DSA-65 and ECDSA using P-256 curve and SHA-256
* Algorithm Usage Location(s): alg
* JOSE Implementation Requirements: Optional
* Change Controller: IETF
* Specification Document(s): RFC XXXX
* Algorithm Analysis Documents(s): {{-COMPOSITE-LAMPS}}

### ML-DSA-87-ES384

* Algorithm Name: ML-DSA-87-ES384
* Algorithm Description: Composite Signature with ML-DSA-87 and ECDSA using P-384 curve and SHA-384
* Algorithm Usage Location(s): alg
* JOSE Implementation Requirements: Optional
* Change Controller: IETF
* Specification Document(s): RFC XXXX
* Algorithm Analysis Documents(s): {{-COMPOSITE-LAMPS}}

### ML-DSA-44-Ed25519

* Algorithm Name: ML-DSA-44-Ed25519
* Algorithm Description: Composite Signature with ML-DSA-44 and Ed25519 using SHA-512
* Algorithm Usage Location(s): alg
* JOSE Implementation Requirements: Optional
* Change Controller: IETF
* Specification Document(s): RFC XXXX
* Algorithm Analysis Document(s): {{-COMPOSITE-LAMPS}}

### ML-DSA-65-Ed25519

* Algorithm Name: ML-DSA-65-Ed25519
* Algorithm Description: Composite Signature with ML-DSA-65 and Ed25519 using SHA-512
* Algorithm Usage Location(s): alg
* JOSE Implementation Requirements: Optional
* Change Controller: IETF
* Specification Document(s): RFC XXXX
* Algorithm Analysis Document(s): {{-COMPOSITE-LAMPS}}

### ML-DSA-87-Ed448

* Algorithm Name: ML-DSA-87-Ed448
* Algorithm Description: Composite Signature with ML-DSA-87 and Ed448 using SHAKE-256
* Algorithm Usage Location(s): alg
* JOSE Implementation Requirements: Optional
* Change Controller: IETF
* Specification Document(s): RFC XXXX
* Algorithm Analysis Document(s): {{-COMPOSITE-LAMPS}}

## COSE Algorithms

The following values are requested to be added to the "COSE Algorithms" registry.
They are represented following the registration template provided in {{RFC9053}}, {{RFC9054}}.

### ML-DSA-44-ES256

* Name: ML-DSA-44-ES256
* Value: TBD (request assignment -54)
* Description: Composite Signature with ML-DSA-44 and ECDSA using P-256 curve and SHA-256
* Capabilities: `[kty]`
* Change Controller: IETF
* Reference: RFC XXXX
* Recommended: Yes

### ML-DSA-65-ES256

* Name: ML-DSA-65-ES256
* Value: TBD (request assignment -55)
* Description: Composite Signature with ML-DSA-65 and ECDSA using P-256 curve and SHA-256
* Capabilities: `[kty]`
* Change Controller: IETF
* Reference: RFC XXXX
* Recommended: Yes

### ML-DSA-87-ES384

* Name: ML-DSA-87-ES384
* Value: TBD (request assignment -56)
* Description: Composite Signature with ML-DSA-87 and ECDSA using P-384 curve and SHA-384
* Capabilities: `[kty]`
* Change Controller: IETF
* Reference: RFC XXXX
* Recommended: Yes

### ML-DSA-44-Ed25519

* Name: ML-DSA-44-Ed25519
* Value: TBD (request assignment -57)
* Description: Composite Signature with ML-DSA-44 and Ed25519 using SHA-512
* Capabilities: `[kty]`
* Change Controller: IETF
* Reference: RFC XXXX
* Recommended: Yes

### ML-DSA-65-Ed25519

* Name: ML-DSA-65-Ed25519
* Value: TBD (request assignment -58)
* Description: Composite Signature with ML-DSA-65 and Ed25519 using SHA-512
* Capabilities: `[kty]`
* Change Controller: IETF
* Reference: RFC XXXX
* Recommended: Yes

### ML-DSA-87-Ed448

* Name: ML-DSA-87-Ed448
* Value: TBD (request assignment -59)
* Description: Composite Signature with ML-DSA-87 and Ed448 using SHAKE-256
* Capabilities: `[kty]`
* Change Controller: IETF
* Reference: RFC XXXX
* Recommended: Yes

--- back

# Examples {#appdx}

## JOSE {#appdx-jose}

~~~~~~~~~~
{::include-fold ./examples/jose/examples/ML-DSA-44-ES256.jose.json}
~~~~~~~~~~
{: #jose_example_ML_DSA_44_ES256 title="ML-DSA-44-ES256"}

~~~~~~~~~~
{::include-fold ./examples/jose/examples/ML-DSA-44-Ed25519.jose.json}
~~~~~~~~~~
{: #jose_example_ML_DSA_44_Ed25519 title="ML-DSA-44-Ed25519"}

~~~~~~~~~~
{::include-fold ./examples/jose/examples/ML-DSA-65-ES256.jose.json}
~~~~~~~~~~
{: #jose_example_ML_DSA_65_ES256 title="ML-DSA-65-ES256"}

~~~~~~~~~~
{::include-fold ./examples/jose/examples/ML-DSA-65-Ed25519.jose.json}
~~~~~~~~~~
{: #jose_example_ML_DSA_65_Ed25519 title="ML-DSA-65-Ed25519"}

~~~~~~~~~~
{::include-fold ./examples/jose/examples/ML-DSA-87-ES384.jose.json}
~~~~~~~~~~
{: #jose_example_ML_DSA_87_ES384 title="ML-DSA-87-ES384"}

~~~~~~~~~~
{::include-fold ./examples/jose/examples/ML-DSA-87-Ed448.jose.json}
~~~~~~~~~~
{: #jose_example_ML_DSA_87_Ed448 title="ML-DSA-87-Ed448"}

## COSE {#appdx-cose}

~~~~~~~~~~
{::include-fold ./examples/cose/examples/ML-DSA-44-ES256.cose.diag}
~~~~~~~~~~
{: #cose_example_ML_DSA_44_ES256 title="ML-DSA-44-ES256"}

~~~~~~~~~~
{::include-fold ./examples/cose/examples/ML-DSA-44-Ed25519.cose.diag}
~~~~~~~~~~
{: #cose_example_ML_DSA_44_Ed25519 title="ML-DSA-44-Ed25519"}

~~~~~~~~~~
{::include-fold ./examples/cose/examples/ML-DSA-65-ES256.cose.diag}
~~~~~~~~~~
{: #cose_example_ML_DSA_65_ES256 title="ML-DSA-65-ES256"}

~~~~~~~~~~
{::include-fold ./examples/cose/examples/ML-DSA-65-Ed25519.cose.diag}
~~~~~~~~~~
{: #cose_example_ML_DSA_65_Ed25519 title="ML-DSA-65-Ed25519"}

~~~~~~~~~~
{::include-fold ./examples/cose/examples/ML-DSA-87-ES384.cose.diag}
~~~~~~~~~~
{: #cose_example_ML_DSA_87_ES384 title="ML-DSA-87-ES384"}

~~~~~~~~~~
{::include-fold ./examples/cose/examples/ML-DSA-87-Ed448.cose.diag}
~~~~~~~~~~
{: #cose_example_ML_DSA_87_Ed448 title="ML-DSA-87-Ed448"}

# Acknowledgments

We thank Orie Steele for his valuable comments on this document.
