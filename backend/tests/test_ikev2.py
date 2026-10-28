import pytest

from app.analyzer import ikev2
from tests import ike_builder as b


def test_hybrid_sa_init_offer_is_decoded():
    msg = ikev2.decode(b.hybrid_sa_init_request())
    assert msg.exchange == "IKE_SA_INIT"
    assert msg.is_initiator and not msg.is_response
    assert msg.offered_ke() == ["CURVE_25519"]
    assert msg.offered_additional_ke() == {"ADDKE1": ["ML_KEM_768"]}
    assert msg.is_pq_hybrid_offer()
    assert msg.ke_method == "CURVE_25519" and msg.ke_data_len == 32
    assert "IKEV2_FRAGMENTATION_SUPPORTED" in msg.notifies
    assert "INTERMEDIATE_EXCHANGE_SUPPORTED" in msg.notifies
    encr = msg.proposals[0].by_type("ENCR")[0]
    assert (encr.name, encr.key_length) == ("AES_GCM_16", 256)
    assert "ADDKE1:ML_KEM_768" in msg.label()


def test_classical_response_is_not_pq():
    msg = ikev2.decode(b.classical_sa_init_response())
    assert msg.is_response and msg.role == "response"
    assert msg.offered_additional_ke() == {}
    assert not msg.is_pq_hybrid_offer()


def test_ppk_notify_detected_without_pq_ke():
    msg = ikev2.decode(b.ppk_sa_init_request())
    assert "USE_PPK" in msg.notifies
    assert not msg.is_pq_hybrid_offer()
    assert "USE_PPK" in msg.label()


def test_intermediate_fragments():
    first = ikev2.decode(b.intermediate_fragment(1, 2))
    second = ikev2.decode(b.intermediate_fragment(2, 2, ciphertext_len=200))
    assert first.exchange == "IKE_INTERMEDIATE" and first.encrypted
    assert first.fragment == (1, 2) and first.inner_first_payload == "KE"
    assert second.fragment == (2, 2) and second.inner_first_payload is None
    assert "frag 1/2" in first.label()


def test_non_esp_marker_handling():
    raw = b.hybrid_sa_init_request()
    assert ikev2.strip_non_esp_marker(b"\x00\x00\x00\x00" + raw, 4500) == raw
    with pytest.raises(ikev2.IKEDecodeError):
        ikev2.strip_non_esp_marker(b"\x01\x02\x03\x04" + raw, 4500)


def test_rejects_garbage():
    with pytest.raises(ikev2.IKEDecodeError):
        ikev2.decode(b"\x00" * 10)
    bad_version = bytearray(b.hybrid_sa_init_request())
    bad_version[17] = 0x10
    with pytest.raises(ikev2.IKEDecodeError):
        ikev2.decode(bytes(bad_version))


def test_unfragmented_intermediate_response():
    msg = ikev2.decode(b.intermediate_sk_response())
    assert msg.exchange == "IKE_INTERMEDIATE" and msg.is_response
    assert msg.encrypted and msg.fragment is None and msg.inner_first_payload == "KE"


def test_truncated_payload_body_is_a_decode_error():
    # a KE payload with an empty body: valid length field, no room for the method id
    with pytest.raises(ikev2.IKEDecodeError, match="truncated KE"):
        ikev2.decode(b.message(34, 34, b.payload(0, b"")))
