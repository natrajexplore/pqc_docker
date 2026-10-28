"""Protocol codepoints the analyzer needs to label post-quantum handshakes.

Source of truth is IANA; every table here is mirrored in docs/PQC_WIRE_REFERENCE.md.
If you change one, change the other, and keep the `verify:` notes honest - several
of these were assigned recently and dissectors lag behind them.
"""
from __future__ import annotations

# ---------------------------------------------------------------- IKEv2 -----
# RFC 7296 exchange types + RFC 9242 IKE_INTERMEDIATE + RFC 9370 IKE_FOLLOWUP_KE
IKE_EXCHANGE = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL",
    43: "IKE_INTERMEDIATE",
    44: "IKE_FOLLOWUP_KE",
}

IKE_PAYLOAD = {
    0: "NONE", 33: "SA", 34: "KE", 35: "IDi", 36: "IDr", 37: "CERT", 38: "CERTREQ",
    39: "AUTH", 40: "Nonce", 41: "Notify", 42: "Delete", 43: "VendorID",
    44: "TSi", 45: "TSr", 46: "SK", 47: "CP", 48: "EAP", 53: "SKF",
}

# Transform types. RFC 9370 renamed type 4 "Key Exchange Method" and added
# Additional Key Exchange 1..7 as types 6..12.
IKE_TRANSFORM_TYPE = {
    1: "ENCR", 2: "PRF", 3: "INTEG", 4: "KE", 5: "SN",
    6: "ADDKE1", 7: "ADDKE2", 8: "ADDKE3", 9: "ADDKE4", 10: "ADDKE5", 11: "ADDKE6", 12: "ADDKE7",
}

# Key Exchange Method IDs (transform type 4 and 6..12).
# verify: ML-KEM 35/36/37 per draft-ietf-ipsecme-ikev2-mlkem / IANA registry.
IKE_KE_METHOD = {
    0: "NONE",
    1: "MODP_768", 2: "MODP_1024", 5: "MODP_1536", 14: "MODP_2048", 15: "MODP_3072",
    16: "MODP_4096", 19: "ECP_256", 20: "ECP_384", 21: "ECP_521",
    31: "CURVE_25519", 32: "CURVE_448",
    35: "ML_KEM_512", 36: "ML_KEM_768", 37: "ML_KEM_1024",
}
PQ_KE_METHODS = {"ML_KEM_512", "ML_KEM_768", "ML_KEM_1024"}

IKE_ENCR = {12: "AES_CBC", 18: "AES_CCM_16", 20: "AES_GCM_16", 28: "CHACHA20_POLY1305"}
IKE_PRF = {2: "HMAC_SHA1", 5: "HMAC_SHA2_256", 6: "HMAC_SHA2_384", 7: "HMAC_SHA2_512"}
IKE_INTEG = {2: "HMAC_SHA1_96", 12: "HMAC_SHA2_256_128", 13: "HMAC_SHA2_384_192", 14: "HMAC_SHA2_512_256"}

# Notify message types (status >= 16384, errors below).
# verify: PPK (RFC 8784) 16435-16437, INTERMEDIATE (RFC 9242) 16438.
IKE_NOTIFY = {
    7: "INVALID_SYNTAX", 14: "NO_PROPOSAL_CHOSEN", 17: "INVALID_KE_PAYLOAD",
    24: "AUTHENTICATION_FAILED", 35: "NO_ADDITIONAL_SAS",
    16388: "NAT_DETECTION_SOURCE_IP", 16389: "NAT_DETECTION_DESTINATION_IP",
    16390: "COOKIE", 16404: "MULTIPLE_AUTH_SUPPORTED", 16406: "EAP_ONLY_AUTHENTICATION",
    16430: "IKEV2_FRAGMENTATION_SUPPORTED", 16431: "SIGNATURE_HASH_ALGORITHMS",
    16435: "USE_PPK", 16436: "PPK_IDENTITY", 16437: "NO_PPK_AUTH",
    16438: "INTERMEDIATE_EXCHANGE_SUPPORTED",
}

# ------------------------------------------------------------------ TLS -----
# verify: pure ML-KEM codepoints per draft-ietf-tls-mlkem; hybrids per
# draft-ietf-tls-ecdhe-mlkem. 0x11ec is what OpenSSL 3.5 negotiates by default.
TLS_GROUP = {
    0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1",
    0x001D: "x25519", 0x001E: "x448",
    0x0200: "MLKEM512", 0x0201: "MLKEM768", 0x0202: "MLKEM1024",
    0x11EB: "SecP256r1MLKEM768", 0x11EC: "X25519MLKEM768", 0x11ED: "SecP384r1MLKEM1024",
    0x6399: "X25519Kyber768Draft00",
}
PQ_TLS_GROUPS = {"MLKEM512", "MLKEM768", "MLKEM1024", "SecP256r1MLKEM768",
                 "X25519MLKEM768", "SecP384r1MLKEM1024", "X25519Kyber768Draft00"}

# verify: ML-DSA TLS SignatureScheme codepoints per draft-ietf-tls-mldsa.
TLS_SIGSCHEME = {
    0x0403: "ecdsa_secp256r1_sha256", 0x0503: "ecdsa_secp384r1_sha384",
    0x0804: "rsa_pss_rsae_sha256", 0x0807: "ed25519", 0x0808: "ed448",
    0x0904: "mldsa44", 0x0905: "mldsa65", 0x0906: "mldsa87",
}
PQ_TLS_SIGSCHEMES = {"mldsa44", "mldsa65", "mldsa87"}

TLS_HANDSHAKE_TYPE = {
    1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket", 8: "EncryptedExtensions",
    11: "Certificate", 13: "CertificateRequest", 15: "CertificateVerify", 20: "Finished",
}
TLS_CONTENT_TYPE = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "ApplicationData"}
TLS_VERSION = {0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}

# ------------------------------------------------------------------ SSH -----
SSH_MSG = {
    1: "DISCONNECT", 2: "IGNORE", 5: "SERVICE_REQUEST", 6: "SERVICE_ACCEPT",
    20: "KEXINIT", 21: "NEWKEYS", 30: "KEX_ECDH_INIT", 31: "KEX_ECDH_REPLY",
    50: "USERAUTH_REQUEST", 51: "USERAUTH_FAILURE", 52: "USERAUTH_SUCCESS",
}
PQ_SSH_KEX = {"mlkem768x25519-sha256", "sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com",
              "mlkem768nistp256-sha256", "mlkem1024nistp384-sha384"}
PQ_SSH_HOSTKEY_MARKERS = ("mldsa",)

# ---------------------------------------------------------- 802.1X / EAP -----
EAPOL_TYPE = {0: "EAP-Packet", 1: "EAPOL-Start", 2: "EAPOL-Logoff", 3: "EAPOL-Key", 5: "EAPOL-MKA"}
EAP_CODE = {1: "Request", 2: "Response", 3: "Success", 4: "Failure"}
EAP_TYPE = {1: "Identity", 3: "NAK", 13: "TLS"}

ETHERTYPE_EAPOL = 0x888E
ETHERTYPE_MACSEC = 0x88E5


def name(table: dict[int, str], value: int | None, fallback: str = "UNKNOWN") -> str:
    if value is None:
        return fallback
    return table.get(value, f"{fallback}({value})")
