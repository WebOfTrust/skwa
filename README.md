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

 
 # Cloud Agent Access control and Key Store Management Architecture

## Why the AEID is Non-transferable

The keys in the key store are encrypted at rest (persistent storage, disk, etc) using assymetric encryption. A public encryption key may be stored on disk and loaded at boot tome so that any new secrets are encrypted. In order to decrypt however, the private decryption key is needed. This must only be provided at run time and must only be stored in memory. Without access to the private decryption key an attacker is not able to discover any encrypted secrets in the keystore. Providing the private decryption key is both an authenticating and authorizing action as it unlocks the encrypted secrets that then may be used to sign. The AEID (Authentication/ Authorization, Encryption ID) is a non-transferable AID derived from an Ed25519 key-pair. The key store asymmetric encryption/decryption key pair is an X25519 key-pair derived from the Ed25519 key pair. Consequently, providing the Ed25519 private key is tantamount to providing the X25519 decryption key. 

Recall that KERI pre-rotation does not prevent compromise of signing keys. It just enables the controller of an identifier to re-establish control over the identifier by revoking the compromised signing key and replacing it with a new one (pre-rotated key). Damage done due to compromise before rotation recovery has occurred is not prevented. As mentioned above, the AEID is used to derive a decryption key to decrypt secrets in the keep (key store). Should that key become compromised then the secrets in the key store may also become compromised. Doing a rotation to revoke the compromised decryption key does not repair the damage of the compromise of the secrets in the key store. That damage is unrecoverable, unrepairable. Consequently there is no advantage to using a transferable identifier that requires a KEL for the AEID. It just adds complexity for no increase in security. Protection from compromise in the first place is essential to protecting a key store of secrets. Consequently the mechanisms that provide the AEID at run time to unlock the secrets and protecting that AEID do not benefit from KERI pre-rotation. 



## Major Variants
There are three major variants of the architecture and several minor variants of each major variant.

The first major variants employs SKWA (Simple KERI for Web Auth) to mutually authenticate a web client (GUI) and a cloud hosted web server run by the controller that also hosts the key store in the cloud of some set of KERI public (indirect mode) AIDs (autonomic identifiers). The web client controller's ID is denoted CCID. The web server's ID is denoted ACID.

The second major variant employs SKWA for the web client to authenticate with locally hosted web server  that also hosts the key store. Because the key store is under local control the local controller but may not authenticate itself to the web client or may only use a non-transferable identifier for that authentication (LCID NT). The web client still authenticates to the local web server using a SKWA CCID.

The third major variant does not employ SKWA at all because both the controller with key store and the web client are local and are bundled together. The bundled processes may either employ no mutual authentication or both the web client and server may mutually authenticate usin non-transferable identifiers (AEID NT and LCID NT).

In all cases the AEID must be provided by the user via the client at boot-up or while running in order to unlock the key store run by the controller. This acts as a type of password-less login when no other mechanism is employed. When other identifiers CCID or ACID or LCID are employed then the private key for each identifier respectively must be provided at boot-up to enable authentication. These private keys then provide a type of password-less login for each respective process.




## Cloud Agent Controller Variant

In the first major variant both the controller and the keep (keystore) for the AIDs reside on a cloud host.  The controller is called a cloud agent controller. In this major variant the cloud agent controller also has a SKWA AID that it uses to authenticate itself to the local web client controller. In this case SKWA is being used in Duo mode to mutually authenticate the cloud agent controller and the web client controller. The SKWA cloud agent controller ID is denoted ACID. The ACID and CCID are used to create an encrypted channel in order that the client may send the AEID private signing key (SigKey) used to derive the keep's private decryption key used to decrypt its secrets.


The minor variants for the first major variant arise from a difference in the configuration of the local web client. In the first minor variant the keep key store authentication and encryption ID (AEID) is distinct from the web client controller's ID (CCID). Recall that the CCID is a SKWA transferable identifier. Whereas the keep AEID is always a non-transferable identifier whose identifier includes its public signature verification key (VerKey). In the second minor variant the AEID key pair is the same as the CCID key pair and whenever the CCID rotates its keys the AEID changes to match. The identifiers are not the same but the key-pairs track. The advantage of the latter approach is the client need only manage one set of key-pairs (current signing and pre-rotated next) for both authentication and encryption as the CCID and AEID share the same keys. Whereas in the former the client must manage two independent sets of key-pairs, one for the CCID and one for the AEID but the AEID key pair is somewhat less exposed.

The following two figures illustrate the minor variants of the first major variant. 

![Variant 1.A](https://i.imgur.com/VkZcopb.png)  
Variant 1.A  

![Variant 1.B](https://i.imgur.com/Z4j8Fqn.png)  
Variant 1.B  




## Local Controller with Cloud Forwarding Agent

In the second major variant the controller and keep for the AIDs reside on a local host and a remote cloud agent forwarder acts as store and forward mailbox for requests to the local controller. In this second major variant the local controller runs two different web servers. The first is remote web server with an external port to connect to the cloud agent forwarder and the second is a local web server with a local port to connect to the web client GUI browser.

The minor variants for the second major variant include the minor variants above plus one more set of variants due a variation that arises from the security postures of the local controller and web client controller.

### Security Posture
When the local controller server process and web client controller browser process are both run locally on a device or devices in the possession of a user (natural person) who controls the keys to both the local controller and the web client controller then those two processes may be deemed to be either fully secure or somewhat secure. It is assumed in this case that the inter-process communication between processes is not observable by an attacker and the the memory of each process is not observable by any attacker. Inter-process communication is generalized to include all forms such as IP (TCP or UDP) and the file system (files, pipes, Unix Domain sockets). To better express this generalization the term local network is used to mean all forms of inter-process communication whether intra-host or inter-host. Obviously secure non-observable inter-host communication may be extremely difficult to achieve. 
When one of these processes is either fully or somewhat secure, i.e. is under control of the user both at boot and while running in protected memory then the process may use a non-transferable (ephemeral, non-rotatable keys) identifier to authenticate itself to the other fully or somewhat secure processes on the same or other devices. Assuming the network is fully secure. This is because (as described previously) the key store does not benefit from pre-rotation and the user may simply change ephemeral identifiers as needed at boot-up of the processes under user control.  

#### Fully Secure
A process running a server or client is deemed to be fully (continuously) secure with respect to user control (authorization) if the device running that process is always in (never leaves) the user's physical possession while running that process including the boot-up of that process by that user and that device never leave's the user's physical possession otherwise. In addition its network connection (inter-process communication) to any other process is also not observable by any attacker. Another way of stating this is the fully secure means that the processes and local network connections between those processes are continuously protected by the user's continuous physical possession of the devices running those processes and the network connections between them. Only the user may boot-up and run a fully secure process on a given device and only that user may observe the inter-process communication between that process and any other process. 

#### Somewhat Secure
A process running a server or client is deemed to be somewhat secure with respect to user control (authorization) if the device running that process is always in the user's physical possession while running that process including the boot-up of that process by that user but the device may not be continuously in the user's possession otherwise. In addition its network connection (inter-process communication) to any other process is also not observable by any attacker.  In this case, the private signing key of a non-transferable KERI AID (ephemeral non-rotatable keys) is entered into the process memory at boot-up by the user in order to authenticate that process to any other local processes. As long as the process runs it will be able to authenticate with the private signing key of its ephemeral ID. The other local processes must be given that ephemeral ID by the user at their boot-up in order to verify the somewhat secure process's signed messages. Should the process stop running then it will lose its private signing key and will no longer be able to authenticate to any other process. 

#### Process and Inter-Process Security
In general modern OSes used for servers and desktops that include the many Unix Variants (Linux, MacOS, BSD) and Windows use protected memory for each process. Once a given process is booted and running no other process may easily observe that processes internal memory. This means that if a process is provided a secret at bootup, which secret only ever resides in that process's internal memory then a later exploit that allows an attacker to run another process even with full root permissions may not easily observe that secret.  If the exploit occurs before the process boots then an attacker with root permissions may have installed a key logger or other observation process that observers the entry of the secret. With regards inter-process communication, if an attacker has full root permissions while any two processes are running and those processes use an operating system shared resource such as the file system which includes pipes and Unix domain sockets or the IP stack then that attacker may easily observe any secrets sent in the clear between those two processes.
Various more sophisticated side channel exploits may allow an attacker to observe secrets even when only in protected memory. This is why the architecture described here is meant to  address the bootstrap of resources that contribute to a threshold structure protection mechanism. 

#### Authentication and Encryption

When a process is deemed fully secure it may send its messages unsigned to the other local processes.  If the inter-process (network) communication is also fully secure then it may send any secrets in the clear to any other fully secure process. If, however, the other process is only somewhat secure but the network is still fully secure then it may send secrets in the clear but only in response to an authenticated request from a somewhat secure process.  

When a process is deemed somewhat secure it must sign its messages to other local processes.

When two communicating processes are both deemed somewhat secure then they must mutually authenticate all requests and responses and must send secrets as encrypted.

When two fully secure communicating processes are communicating over a network that is also not fully secure then the processes must behave as if they are both only somewhat secure, that is, they mutually authenticate and only send secrets encrypted.

To clarify, when a process is deemed to be fully secure with respect to user control it does not need to authenticate itself to other local processes also under user control either fully or somewhat secure. When a process is deemed somewhat secure with respect to user control it needs to authenticate itself  to other local processes also under user control either fully or somewhat secure. It may use a  non-transferable (ephemeral) KERI self-certifying identifier (non-rotating keys) for that authentication. 


### Local Variants


When the local controller is fully secure but the web client is somewhat secure  then there is no need to authenticate the local controller to the web client but there is still a need to authenticate the web client to the local controller. In this case the local controller does not authenticate to the local web client controller but the web client controller still authenticates to the local controller. Likewise the communication of the AEID private signing key (SigKey) from the client to the controller is not encrypted because it is only stored in memory and given that the AEID SigKey is already in the possession of a somewhat secure web client controller then sending the AEID SigKey in the clear from a somewhat secure web client to a fully secure local controller does not detract from its security as long at the AEID SigKey is only ever stored in memory on both. 

Conversely, when the local controller is somewhat secure then it employs a non-transferable identifier created at boot time to authenticate itself to the client. This local controller identifier is denoted LCID. The LCID is also used with the CCID to create an encrypted channel to encrypt the communication of the AEID in order that the client may send as encrypted the AEID private signing key (SigKey) used to derive  the keep's private decryption key used to decrypt its secrets.

The following four figures illustrate the minor variants of the second major variant. 


![Variant 2.A](https://i.imgur.com/CMMz6h1.png)  
Variant 2.A  

![Variant 2.B](https://i.imgur.com/Zy4CVut.png)  
Variant 2.B  

![Variant 2.c](https://i.imgur.com/wDhETsi.png)  
Variant 2.C  

![Variant 2.D](https://i.imgur.com/vQ3br3c.png)  
Variant 2.D  


## Bundled Local Controller and local Web Client Controller with Cloud Forwarding Agent

In the third major variant a self-contained bundled application is created using Electron and PyInstaller. The bundle includes both the python local controller process and javascrypt web application client browser process. 

When the bundle is fully secure then the local controller and web client controller may be treated as the same controller. The AEID private signing key (SigKey) may then be used as a password-less login by the user to authenticate the user to the bundle and unlock the secrets in the key store. This also implicitly authorizes the bundle to perform singing operations on the user's behalf. The AEID (SigKey) must only be stored in memory. The bundle application may further enhance security by timing out after some brief period of inactivity on behalf of the user so that the user has to re-enter the AEID SigKey. This provides a timed session that prevents unattended access to the user interface of the bundle.

When the bundle is only somewhat secure as may be the case when the interprocess communication within the bundle is not fully secure (observable by an attacker) then both processes mutually authenticate using a nontransferable identifier. The local controller uses the LCID and the web client controller uses the AEID. In this case secrets sent between the processes are encrypted.

The advantage of the bundle is that SKWA is not required and in both the fully secure case and somewhat secure cases only the minimum amount of key management is required for the user.

The following two figures illustrate the minor variants of the third major variant. 

![Variant 3.A](https://i.imgur.com/XdzUGhl.png)  
Variant 3.A  

![Variant 3.B](https://i.imgur.com/ehnbmqC.png)  
Variant 3.B  


## Cloud Bootstrap Procedures

### Cloud Agent Controller

Upon first boot-up of the cloud agent controller  server process the IT person must create the SKWA ACID and inject its signing key to be stored in memory. The ACID does not use the keep to manage its keys. They must be manged externally by the IT person responsible for managing the Cloud Agent Server process. The IT person may use SSH to setup and configure the Cloud Agent Server Process. The ACID private keys must never be persisted on the server but only in memory at boot up of the process. Every time the process is rebooted the private key must be re-injected by the IT admin.

The ACID identifier must be published or shared with the web client controller using an OOB (Out-Of-Band) mechanism.

Likewise the config of the cloud agent must include the CCID of the web client controller that was shared to the IT admin via an OOB mechanism.

The pair ACID-CCID may now mutually authenticate and create a DH (Diffie-Hellman) key exchange so that the Web Client may initialize the keep with its AEID private signing key (SigKey) used to created the keep's encryption/decryption keys.

### Web Client Controller

The web client controller creates a key pair and uses that to create a SKWA CCID. The user of the web client controller must inject that private signing key into memory on the browser. The CCID must be shared via OOB mechanism to the IT person managing the cloud agent. Likewise the ACID is shared with the web client user.

The CCID private keys are never persisted in browser persistent storage but must only reside in memory. Every time the user restarts a browsing session with the cloud agent the private signing key for the CCID must be re-injected.

The pair ACID-CCID may now mutually authenticate and create a DH (Diffie-Hellman) key exchange so that the Web Client may initialize the keep with its AEID private signing key (SigKey) used to created the keep's encryption/decryption keys.

### Cloud Agent Forwarder (Mailbox)
The Cloud Agent Forwarder uses a non-transferable AID denoted AFID. It uses its AFID to sign messages it forwards to the local controller so that the local controller may authenticate that those messages came from a recognized forwarder. The IT person responsible for managing the forwarder creates the AFID on boot-up and injects its private key into memory. The key may also be stored on disk because the forwarder itself is not controlling a KEL. A compromised forwarder key merely is a DDOS attack not a security attack. The IT person shares the AFID with the local controller using an OOB mechanism. The local controller then stores the AFID as a recognized forwarder similar to a watcher. A given configuration may choose to employ a pool of forwarders that share forwards in order to provide high availability. The local controller may then choose to load balance its use of any given forwarder.


### When CCID and AEID share the same key pair.

In this case there must be logic in the controller to check any attempt to change the AEID so that it matches a authenticated rotation of the CCID.

Sharing keys between the CCID and AEID may significantly simplify key management on the part of the web client user because that user need only protect one set of key pairs instead of two. In this case when the CCID is rotated then a new non-transferable AEID is created using the new CCID key pair. This provides no security advantage but merely simplifies key managment for the web client user. 

In this case (shared keys between) the CCID and AEID, the private signing key used to derive the private decryption key is more exposed through its use to sign requests from the web client to the server controller. EdDSA (Ed25519) digital signing keys are meant to be used for signatures in volume and are designed to be highly resistant to attack. The Libsodium version of Ed25519 (Ed25519-IETF) has been shown to be SUF-CMA (Strong Unforgeability to Chosen Message Attack) and is highly resistant to key substitution attacks [Provable Security of Ed25519](https://eprint.iacr.org/2020/823.pdf). SUF-CMA is the highest level of strength for digital signatures and makes it extremely unlikely that an adversary could ever forge a valid signature without knowing the private key in spite of a corpus of signed messages. Consequently increased weakness as a result of exposure due to more frequent use when sharing keys for both the CCID and AEID may not be significant. Nonetheless out of caution when the CCID and AEID share the same keys then the keys should be rotated more frequently than when not.


# Keri Request Authentication Mechanism  (KRAM)


See this here:  https://github.com/WebOfTrust/kram/blob/main/README.md


# Hackmd Source Documents

https://hackmd.io/AXJ35eciSCa04FtG5Yg9Zg

https://github.com/WebOfTrust/keri-skwa.git

https://hackmd.io/2xIuooE1Qk6mkSHdx01uJA

https://hackmd.io/ZbVAbNK1SPyT90-oNwN_cw
