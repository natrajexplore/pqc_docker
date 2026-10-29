# Demo script (about 12 minutes)

For a meetup, interview panel, or a recorded walkthrough. Each beat lists what
to click and what to say; the scenario narration fields show the key line on
screen while the step runs, so you can follow the UI rather than notes.

Before you start: `make up`, run every scenario once (warms images and PKI),
open the UI at 127.0.0.1:8080 and press **P** for presenter mode: the ladder goes
full width and the current narration line becomes a large caption (Esc leaves it).
For slides, *Copy SVG* / *Download SVG* under the ladder export it with the light
theme.

All numbers below are from real runs in this lab (see the README's measured results).

## 1. The problem (1 min, no clicks)

"Every secure connection does two jobs: agree a key, and prove who you are. A
quantum computer threatens both, on different clocks. Key exchange is urgent,
because traffic recorded today can be decrypted later. Authentication has a
later deadline, but certificates and CAs live for years."

## 2. Classical IKEv2 (1.5 min) - `ipsec-kex-classical`

Run it. Point at the ladder: two thin amber IKE_SA_INIT arrows, two grey
(encrypted) IKE_AUTH arrows, then the ESP row. "This is what your VPN looks like
today: about 1 KB of handshake and two round trips."

## 3. Hybrid ML-KEM (2 min) - `ipsec-kex-hybrid-mlkem768`

Run it. "Same X25519, plus ML-KEM-768 in a new exchange called IKE_INTERMEDIATE.
See how the arrows thicken, and the dashed one: ML-KEM's key doesn't fit in one
message, so it's fragmented." Click the IKE_SA_INIT response: show ADDKE1
ML_KEM_768 decoded from the cleartext bytes. Verdict: key exchange green and
"seen on the wire"; authentication amber, because it's still a PSK.

**Compare runs**: "about three times the bytes, one extra round trip, a few
milliseconds. That's the price of quantum-safe keys."

## 4. TLS does it without the extra trip (1.5 min) - `tls-kex-hybrid`

"Same hybrid, TLS 1.3. The 1216-byte key share rides in the ClientHello. No new
round trip. OpenSSL 3.5 does this by default."

## 5. The size explosion (2 min) - `ipsec-auth-ecdsa` vs `ipsec-auth-mldsa65`

Run both, then compare. "Now authentication. ML-DSA-65 signatures are 3.3 KB.
IKE_AUTH goes from 2 messages to 16 - eight fragments each way - and the handshake
from about 5 KB to 23 KB. Cisco measured 7 frames becoming 20 on real routers - this
is why ML-DSA needs a maintenance window, not just a config change." Note the
authentication verdict says *endpoint*: IKE_AUTH is encrypted, so the certificate
algorithm comes from the peer, not the wire.

## 6. The silent downgrade (2 min) - `macsec-downgrade-tls12`, then `macsec-downgrade-pinned-client`

"MACsec's weak spot is the EAP-TLS handshake. Remove one line on the
authenticator..." Run it. "EAP says success. Every log is green. But the wire
says TLS 1.2 - ML-KEM is gone. The run is red because the capture disagrees with
the logs." Then run the pinned client: "Pin TLS 1.3 on the supplicant and the
same mistake fails closed. That's the behaviour you want."

## 7. SSH already did this (1 min) - `ssh-kex-default`, `ssh-kex-downgrade`

"No configuration: ML-KEM by default." Then the downgrade: "This server only offers
classical key exchange - and the client prints a WARNING that the session isn't
post-quantum." (OpenSSH stays quiet if the *client* forces classical itself; it
only warns when the other side imposes it.)

## 8. Close (1 min)

"Key exchange first, it's cheap. Pin TLS 1.3 everywhere EAP runs. Plan ML-DSA
around release numbers and handshake size. And measure on the wire - logs said
'success' on a classical session two minutes ago."

Optional: import a router EPC capture and compare it with the container run.
