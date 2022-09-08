# Simple KERI for Web Auth (SKWA) Specification

## Limited Feature KERI Implementation

The full featured KERI protocol is designed to support nearly every imaginable application that requires secure attribution at scale. As a result, a full featured implementation of KERI may be quite complex. The design principles of KERI are in order of priority security, performance, usability (convenience). Obviously KERI is security first always. Performance is second because it may be problematic to add performance features to a protocol design after the fact. But not all applications of KERI require performance. Some narrow applications may benefit from an implementation that sacrifices performance or other non-security feature for usability. In general a narrow application of KERI may not require all the features of KERI but those features that it does support must still be secure.

## Web Application Authentication and Authorization

One such narrow or limited feature application is authentication of a client web browser to a web server running in the cloud to support an interactive web graphical user interface (Web GUI). Authentication in this sense means proving control of a transferable KERI AID  to a ReST endpoint on the server by signing a client HTTP request with the private key that is the current signing key for that AID. The authenticated request may also be used to authorize the server to perform some task on behalf of the controller of that identifier. The primary feature benefit of using a transferable KERI AID for the identifier is that the key-pair that controls the identifier is rotatable using KERI's pre-rotation mechanism. This provides a more secure key rotation mechanism than is provided by most if not all other web authentication mechanisms including WebAuthn.

SKWA basically just needs those features of KERI necessary for pre-rotation of single key-pair transferable identifiers. It is meant to support users who merely wish to interact with a web application for tasks that require user interaction.  SKWA is not intended to support interactions at scale by any given user on the client side. With SKWA a server may use a full KERI implementation to interact with a SKWA only client because SKWA is a proper subset of KERI. 

To reiterate, SKWA is not meant for micro-service backends that support complex web applications nor is SKWA meant to support identifiers that directly issue verifiable credentials or multi-sig identifiers etc etc. It is only meant to support the AuthN/AuthZ of an interactive web application client with pre-rotation of its controlling key-pair.

One interactive web application task that SKWA is designed to support specifically is the management of web resources that support a full featured implementation of KERI that in turn support a public KERI AID that is used to issue verifiable credentials at scale. In other words an identifier supported by a lightweight SKWA implementation may be used as a secure bootstrap to manage resources for identifiers supported by a more heavyweight full KERI implementation. Once bootstrapped the SKWA identifier may be used to authorize business logic associated with that public KERI AID or to authorize participation of a single-sig member of a multi-sig group.


## Required Features of SKWA

The required KERI features that a SKWA Node implementation must support are as follows:

- Events are standard KERI but with the limitations as defined below.  
- Communication uses HTTP 1.1  
- Browser nodes may use the Javascript IndexedDB API to store KELs  
- Node identifier must be a KERI AID that is transferable, non-delegated, non-delegating, establishment only (no disputed IXN events), self-addressing, self-certifying, single-sig (one signing key-pair and one next pre-rotated key-pair),  with no-backers and uses only Ed25519 key-pairs for the current and next keys with a Blake3 for the the next key commitment.  
- All primitives use appropriate CESR encodings  
- All request/response bodies are JSON  mime type is application/json.  
- Signed request/response bodies Must provide the signature(s) with the KERI HTTP Signature header  (Signature header uses structured fields compliant with RFC-8941 (Structured Field Values for HTTP) [KERI HTTP Signature Header](https://hackmd.io/65pKx1mVTq6DQv7loF7_Dw)  
- Key events request/response bodies must use JSON as the serialization type with corresponding version string and use KERI signature header for the attached signature(s).  
- key event prior event digests must use Blake3  
- Requests from client that convey KERI Key Events   
- All requests must use KRAM (KERI Request Authentication Method) for reply attack protection. Essentially this means each request body includes a date time string field in ISO-8601 format that must be within an acceptable time window relative to the server's date time. The server may enhance replay attack prevention by requiring that all requests from a given client identifier have monotonically increasing datetimes that are within the server's window of acceptable date-times. [KRAM](https://hackmd.io/ZbVAbNK1SPyT90-oNwN_cw)  
- All KERI events may be sent in non-streaming mode (i.e. recipients do not need a stream parser). Any attached data such as signatures must use an HTTP header (i.e. no attachments to events)  
- Escrow is not supported. This means all events must be in-order with all signatures provided in the Signature header. Any out-of-order or partially signed events may be discarded.   
- Receipts on KERI events are not supported. The full event with all attached signatures must be sent.  
- Anchors in events are not supported. The anchor field should be empty.  


## Operation Modes
A SKWA node operates in one of two modes, duo and solo, both of which are a subset of KERI Direct Mode. Direct mode does not require witnesses or other backers. SKAW forbids backers on SKWA node identifiers, that is, they must have empty backer lists in all establishment events.

### Duo Mode

In duo mode the client and server each use a SKWA identifier for mutual authentication. Client requests are signed by the client node's SKWA identifier and server responses are signed by the server node's SKWA identifier. Some out-of-band mechanism is required to mutually establish the pair of identifiers for the duo mode connection by sharing with to each member in the duo. This is to prevent impostor or man-in-the-middle attacks on the connection.

For example, suppose a given user wants to spin up a cloud server and wants the server to only accept requests from a given client SKWA node identifier (AID) under the user's control. The user may do this by adding the client node's SKWA AID to a configuration file on the server. Later when the server is running it checks its configuration file and only processes requests if they are verifiably signed by the authoritative keys for that client node identifier. Likewise when configuring the server the user saves or copies the server's SKWA node identifier so that the client node may verify that it is interacting with the correct server and not some impostor or man-in-the middle.  

The server may employ a full featured implementation of KERI but must use only the subset of features supported by SKWA for its interaction with the SKWA client.


### Solo Mode

In solo mode the server is either deemed by the client node to be fully secure with respect to client control and therefore does not need to be authenticated by the client or the server is deemed to be somewhat secure and needs to be authenticated by the client but may be authenticated with a non-transferable (ephemeral) KERI self-certifying identifier (non-rotating keys). Solo mode is predicated on the fact that server is under the control of the client either continuously or at least at boot up of the server process into protected memory. Therefore the server does need a transferable identifier with rotatable keys because the client may simply change the ephemeral identifier as needed at boot-up.

To further elaborate, the server may be deemed fully (continuously) secure because the server never leaves the client's physical possession and the client also has a continuously protected local connection to the server. The server may be deemed somewhat secure if it was in the client's control at boot-up but may not be continuously in the client's control through out its run time. In this latter (somewhat secure) case, an ephemeral private key is entered into the server's memory at boot-up by the client. As long as the server runs it will be able to authenticate with its ephemeral ID. The client knows the ephemeral ID because the client provided it to the server at boot up. Should the server stop running then it will lose its ephemeral key and will no longer be able to authenticate to the client. 

When the server is deemed fully secure it does not sign its messages to the client and secrets may be sent in the clear to the client but only in response to authenticated client requests. When the server is deemed somewhat secure it signs its messages to the client and secrets must be encrypted and only sent in response to authenticated client requests.

All client requests must be signed by the authoritative keys of the client to protect the server from attack. When the server is not fully secure the client must also encrypt any secrets sent to the server. 

For example suppose the server is running on a device in the physical possession of the client user and the server only exposes a localhost port. The only client that may attach to the server is one running on that device. Assuming the computer itself is offline and not connected to the internet then the client may trust that the server on that localhost port is indeed the server the user configured. Nonetheless the server itself must still be configured to only accept requests from the SKWA AID of the client in the event that the client loses control of the server and a malicious client attaches to the server. 

## SKWA Node Key Managment
 
Because SKWA only support single-sig mode, that is, there is only one authoritative signing key-pair at a time, the complexity of key creation and storage is minimized. A SKWA node must store two private keys at any time. One key is the current signing key and the other key is the next pre-rotated key. Recall that in KERI that the next pre-rotated key is a one-time rotation key. After it is used one time to sign a rotation it becomes the signing key for all client requests until the next rotation event when it becomes defunct and is replaced by the next pre-rotated key. To clarify, at any point in time two private keys must be stored, the current signing key and the next pre-rotated key. When performing a rotation, a new pre-rotated key must be created, the old pre-rotated key becomes the new signing key and the old signing key is discarded.

In addition to creating and storing the two private keys, SKWA key management requires generating the Ed25519 public key of each of the two private keys and also generating a Blake3 hash of the public key of the next key.

One approach to providing these key management functions is to use a key manage such as 1Password, Dashlane, LastPass or RoboForm in conjunction with  a standalone app or utility (not browser based) that generates key pairs and the next key hash.  In stead of the standalone app, an alternative web browser based approach would be to have an in memory function that created the key pairs and the next key hash with the caveat that it be run only in offline mode when creating the next key hash as this exposes the next private key outside of the key store prior to a rotation in which it is used to sign. 

Support from hardware security modules for the key management functions may also be possible.

## Signing

The most convenient approach to signing is that client node requests are signed by code running on the client browser. This requires that the current signing private key be entered into browser memory. For security reasons, this private key must memory only and deleted at the end of any online session. It must not be stored on disk or other browser persistent storage such as LocalStorage or IndexedDB storage.  Strict CORS control must be in place. The browser should be run in safe mode that may include disabling all plugins and extensions. This limits the attack surface for compromising the signing key.

When performing a rotation the private key of the next pre-rotated key is entered into memory in order to sign the rotation event. The old signing key may be deleted. The rotation event also requires a Blake3 hash of the newly pre-rotated public key. In the case that there is no offline tool for generating the public key and hash of the next pre-rotated key then the browser must be put in an offline mode to perform that function and the then next private key must be deleted from memory before putting the browser back online.

Notwithstanding the foregoing, any use case that places the next private key in browser memory may expose it to a browser based side channel attack. A better approach is to use a non-browser based tool or app to create the next key digest in order to create an inception or rotation event. 

## SKWA Encrypted Communication

The Ed25519 signature key-pair of the SKWA identifier may be converted to an X25519 encryption/decryption key=pair. Depending on the operation mode (solo, or duo) This enables encrypted messages to sent to or from a SKWA node. 
The specific format of an encrypted message body may be ReST API dependent. A suggested approach is to use a JSON body with a designated field whose value is the encrypted data in either CESR or Base64 format. Other fields in the body can indicate the details of the encrypted field if not obvious from the context. Another approach would use the whole message body for the encrypted data with a mime-type of text/plain with a header (TBD) to provide the encryption suite and appropriate identifiers. 

Currently CESR supports codes X25519 encrypted salts (16 byte) and seeds (32 byte). The type of seed is context dependent. A future CESR code for variable length encrypted data may be specified. 

### Asymmetric Encryption
LibSodium supports the secret-box asymmetric encryption/decryption. In solo mode, the SKWA node may use the X25519 equivalent of its Ed2519 key pair to either encrypt messages using the X25519 pubic key that it stores encrypted. It may decrypt those messages with its X25519 private key. Or another node or server may use the X25519 public key to encrypt messages to send to that SKWA node. A given ReST endpoint API may indicate 

### Symmetric DH Encryption
Libsodium also supports crypto-box symmetric encryption. Cypto-box symmetric encryption uses a Diffie-Hellman key exchange to create a shared secret that is then used a shared key to both encrypt and decrypt messages. Symmetric DH encryption works in Duo mode. Each node has an Ed25519 public key-pair from which an X25519 key pair may be created. Each node may share with the other node its Ed25519 public key (from which the other node may create the corresponding X25519 public key) that may then be used with its own X25519 private key to create the shared symmetric key. The two nodes may then send encrypted message to each other.


## Suggestion Libraries

- IndexedDB API for the KEL database on client.  

- ibsodium.js package for the Ed25519 key-pair derivation signature key conversion and encryption/decryption operations.  

- Blake3 javascript package for the Black3 hash. This package has a rust wasm for the browser and a rust node.js for the server when using node.js on the server.  

# Enhanced SKWA with Full KEL/KERL Validation

One very useful enhancement to SKWA is to add support for the validation of the in-order, self-contained,  last-event-only (unforked), replay of a KEL or KERL for a non-SKWA limited AID. Recall that technically a KEL is a key event log with attached signatures and a KERL is a KEL that also includes the attached receipts of the witnesses. A direct-mode KERI AID has no witnesses while an indirect mode KERI AID does. Typically  for convenience, however, the term KEL may used to refer to both a proper KEL and a KERL unless it is not clear from the context. 

An in-order, self-contained, last-event-only, replay of a KEL/KERL has the following properties:

- All events appear in order of sn.
- All events include as immediate attachments all controller signatures and witness receipts.
- All events are the last event at a given sn from the set of events at that sn that arise from recovery rotation events.

The in-order and immediate attachment requirements ensure that the Enhanced SKWA node may validate a KEL without needing asynchronous escrow processing of events. The requirement of last-only-events ensures that the Enhanced SKWA node may validate without the need to store KELs with forks of disputed events. This means that an enhanced SKWA node is thereby limited in its ability to detect or reconcile duplicity. It may have to depend on an external watcher, judge, or juror for that. 

Validation of delegated identifiers by an enhanced SKWA imposes the following limitations on the replay of multiple KELs/KERLs:

- The replay of any delegating KEL must appear before the replay of any of its delegated KELs.  

Validation of TELS by an enhanced SKWA impose similar in-order, self-contained, last-event-only constraints on the replay of the TEL. An additional constraint is as follows:

- The replay of any issuing KEL must appear before the replay of any of its associated TELS

With the addition of verifiable credential validaton logic the foregoing capabilities would allow an enhanced SKWA to validate the issuance or revocation status of a verifiable credential.


Essentially an enhanced SKWA implementation may be used to validate KELs for full KERI AIDS but is not able to use its own AID to perform more sophisticated functions like issuing verifiable credentials or delegating identifiers or using indirect-mode.

 
 

https://hackmd.io/AXJ35eciSCa04FtG5Yg9Zg

https://github.com/WebOfTrust/keri-skwa.git

