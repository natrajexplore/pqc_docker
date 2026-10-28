---
description: Independently cross-check a run's verdict against its raw pcap with tshark
argument-hint: <run-id>
---

Audit run `$ARGUMENTS` without trusting our analyzer.

1. Fetch `GET /api/runs/$ARGUMENTS` and note the verdict, metrics and pcap path.
2. Inside the backend container, decode the pcap with plain tshark filters, for example:
   - IKEv2: `-Y isakmp -T fields -e frame.number -e isakmp.exchtype -e frame.len`, and
     `-Y "isakmp.exchtype==34" -V` to read the SA transforms by eye
   - TLS: `-Y "tls.handshake.type==2" -T fields -e tls.handshake.extensions_key_share_group -e tls.handshake.extensions.supported_version`
   - SSH: `-Y "ssh.message_code==20" -T fields -e ssh.kex_algorithms -e ssh.server_host_key_algorithms`
   - EAPOL: `-Y eapol | wc -l`, then the TLS fields above
3. Recompute handshake bytes, frame count and fragments yourself.
4. Produce a short table: our value vs independent value for each claim, and say
   plainly whether the verdict's evidence label (wire / endpoint / declared) is justified.
5. If they disagree, find the bug in `backend/app/analyzer/` and write a failing test first.
