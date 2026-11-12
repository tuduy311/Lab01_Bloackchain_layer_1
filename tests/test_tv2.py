"""Tests for TV2: Models, Crypto, Execution modules."""

import pytest
import sys
import os

# Ensure the project root is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.models import (
    Block, Transaction, Vote, Phase, Message, MessageType,
    FinalizeCertificate, NIL_BLOCK_ID, genesis_block, _canonical_json,
)
from src.crypto import (
    generate_keypair, sign, verify, sha256_hex,
    compute_block_id, sign_block, verify_block_signature, verify_block_id,
    sign_vote, verify_vote_signature,
    sign_transaction, verify_transaction_signature,
    public_key_from_private,
)
from src.execution import (
    AccountState, WorldState, TxResult,
    validate_transaction, apply_transaction, execute_block,
    create_genesis_state,
)


# =========================================================================
# Helpers
# =========================================================================

def _make_keypair():
    priv, pub = generate_keypair()
    return priv, pub


def _make_signed_tx(sender_priv, sender_pub, receiver_pub, amount, nonce):
    tx = Transaction(sender=sender_pub, receiver=receiver_pub,
                     amount=amount, nonce=nonce)
    return sign_transaction(tx, sender_priv)


# =========================================================================
# Models tests
# =========================================================================

class TestTransaction:
    def test_canonical_bytes_deterministic(self):
        tx1 = Transaction("aaa", "bbb", 100, 0)
        tx2 = Transaction("aaa", "bbb", 100, 0)
        assert tx1.canonical_bytes() == tx2.canonical_bytes()

    def test_canonical_excludes_signature(self):
        tx1 = Transaction("aaa", "bbb", 100, 0, signature="")
        tx2 = Transaction("aaa", "bbb", 100, 0, signature="deadbeef")
        assert tx1.canonical_bytes() == tx2.canonical_bytes()

    def test_roundtrip_dict(self):
        tx = Transaction("aaa", "bbb", 42, 7, "sig123")
        assert Transaction.from_dict(tx.to_dict()) == tx


class TestBlock:
    def test_canonical_excludes_block_id_and_sig(self):
        b1 = Block(height=1, round=0, parent_id="p", block_id="", signature="")
        b2 = Block(height=1, round=0, parent_id="p", block_id="xyz", signature="sig")
        assert b1.canonical_bytes() == b2.canonical_bytes()

    def test_roundtrip_dict(self):
        tx = Transaction("s", "r", 10, 0, "sig")
        b = Block(height=1, round=2, parent_id="p", transactions=(tx,),
                  proposer_id="prop", timestamp=1.5, block_id="bid", signature="bsig")
        assert Block.from_dict(b.to_dict()) == b


class TestVote:
    def test_nil_vote(self):
        v = Vote(1, 0, Phase.PREVOTE, NIL_BLOCK_ID, "voter1")
        assert v.is_nil

    def test_canonical_deterministic(self):
        v1 = Vote(1, 0, Phase.PREVOTE, "block1", "v1")
        v2 = Vote(1, 0, Phase.PREVOTE, "block1", "v1")
        assert v1.canonical_bytes() == v2.canonical_bytes()

    def test_roundtrip_dict(self):
        v = Vote(1, 0, Phase.PRECOMMIT, "block1", "v1", "sig")
        assert Vote.from_dict(v.to_dict()) == v


class TestMessage:
    def test_roundtrip(self):
        m = Message(MessageType.PROPOSAL, "node1", 1, 0, {"key": "val"})
        assert Message.from_dict(m.to_dict()) == m


class TestFinalizeCertificate:
    def test_roundtrip(self):
        v = Vote(1, 0, Phase.PRECOMMIT, "bid", "v1", "sig")
        cert = FinalizeCertificate(1, 0, "bid", (v,))
        assert FinalizeCertificate.from_dict(cert.to_dict()) == cert


class TestGenesis:
    def test_genesis_block_id_is_valid(self):
        g = genesis_block()
        assert g.height == 0
        assert g.round == 0
        assert g.block_id
        assert verify_block_id(g)

    def test_genesis_deterministic(self):
        g1 = genesis_block()
        g2 = genesis_block()
        assert g1.block_id == g2.block_id


# =========================================================================
# Crypto tests
# =========================================================================

class TestCryptoBasic:
    def test_sha256_hex(self):
        h = sha256_hex(b"hello")
        assert len(h) == 64
        assert h == sha256_hex(b"hello")  # deterministic

    def test_keypair_lengths(self):
        priv, pub = generate_keypair()
        assert len(priv) == 64   # 32 bytes hex
        assert len(pub) == 64

    def test_sign_verify(self):
        priv, pub = generate_keypair()
        data = b"test message"
        sig = sign(data, priv)
        assert verify(data, sig, pub)

    def test_wrong_key_fails(self):
        priv1, pub1 = generate_keypair()
        _, pub2 = generate_keypair()
        sig = sign(b"x", priv1)
        assert not verify(b"x", sig, pub2)

    def test_tampered_data_fails(self):
        priv, pub = generate_keypair()
        sig = sign(b"original", priv)
        assert not verify(b"tampered", sig, pub)

    def test_public_key_from_private(self):
        priv, pub = generate_keypair()
        assert public_key_from_private(priv) == pub


class TestBlockCrypto:
    def test_sign_and_verify_block(self):
        priv, pub = generate_keypair()
        b = Block(height=1, round=0, parent_id="p", proposer_id=pub)
        signed = sign_block(b, priv)
        assert signed.block_id
        assert signed.signature
        assert verify_block_id(signed)
        assert verify_block_signature(signed, pub)

    def test_block_id_changes_with_content(self):
        b1 = Block(height=1, round=0, parent_id="p")
        b2 = Block(height=1, round=1, parent_id="p")  # different round
        assert compute_block_id(b1) != compute_block_id(b2)


class TestVoteCrypto:
    def test_sign_and_verify_vote(self):
        priv, pub = generate_keypair()
        v = Vote(1, 0, Phase.PREVOTE, "block1", pub)
        signed = sign_vote(v, priv)
        assert signed.signature
        assert verify_vote_signature(signed, pub)

    def test_wrong_key_fails_vote(self):
        priv, pub = generate_keypair()
        _, pub2 = generate_keypair()
        v = Vote(1, 0, Phase.PREVOTE, "block1", pub)
        signed = sign_vote(v, priv)
        assert not verify_vote_signature(signed, pub2)


class TestTransactionCrypto:
    def test_sign_and_verify_tx(self):
        priv, pub = generate_keypair()
        tx = Transaction(sender=pub, receiver="recv", amount=50, nonce=0)
        signed = sign_transaction(tx, priv)
        assert signed.signature
        assert verify_transaction_signature(signed)

    def test_wrong_key_fails_tx(self):
        priv1, pub1 = generate_keypair()
        priv2, pub2 = generate_keypair()
        tx = Transaction(sender=pub1, receiver="recv", amount=50, nonce=0)
        # Sign with wrong key
        signed = sign_transaction(tx, priv2)
        # Verification uses tx.sender (pub1) → should fail
        signed_bad = Transaction(sender=pub1, receiver="recv",
                                 amount=50, nonce=0, signature=signed.signature)
        assert not verify_transaction_signature(signed_bad)


# =========================================================================
# Execution tests
# =========================================================================

class TestWorldState:
    def test_new_account_defaults(self):
        ws = WorldState()
        acc = ws.get_account("addr1")
        assert acc.balance == 0
        assert acc.nonce == 0

    def test_credit_debit(self):
        ws = WorldState()
        ws.credit("a", 100)
        assert ws.get_balance("a") == 100
        ws.debit("a", 30)
        assert ws.get_balance("a") == 70

    def test_copy_isolation(self):
        ws = WorldState()
        ws.credit("a", 100)
        ws2 = ws.copy()
        ws2.debit("a", 50)
        assert ws.get_balance("a") == 100  # original unchanged
        assert ws2.get_balance("a") == 50

    def test_state_root_deterministic(self):
        ws1 = WorldState()
        ws1.credit("a", 100)
        ws1.credit("b", 200)
        ws2 = WorldState()
        ws2.credit("b", 200)
        ws2.credit("a", 100)  # different order, same result
        assert ws1.state_root() == ws2.state_root()

    def test_roundtrip_dict(self):
        ws = WorldState()
        ws.credit("a", 100)
        ws.increment_nonce("a")
        ws2 = WorldState.from_dict(ws.to_dict())
        assert ws2.get_balance("a") == 100
        assert ws2.get_nonce("a") == 1


class TestGenesisState:
    def test_create_genesis_state(self):
        gs = create_genesis_state({"alice": 1000, "bob": 500})
        assert gs.get_balance("alice") == 1000
        assert gs.get_balance("bob") == 500


class TestTransactionExecution:
    def test_valid_transfer(self):
        priv, pub = _make_keypair()
        _, recv = _make_keypair()
        state = create_genesis_state({pub: 1000})
        tx = _make_signed_tx(priv, pub, recv, 100, 0)

        result = apply_transaction(tx, state)
        assert result.success
        assert state.get_balance(pub) == 900
        assert state.get_balance(recv) == 100
        assert state.get_nonce(pub) == 1

    def test_insufficient_balance(self):
        priv, pub = _make_keypair()
        _, recv = _make_keypair()
        state = create_genesis_state({pub: 50})
        tx = _make_signed_tx(priv, pub, recv, 100, 0)

        result = apply_transaction(tx, state)
        assert not result.success
        assert "insufficient" in result.error
        assert state.get_balance(pub) == 50  # unchanged

    def test_wrong_nonce(self):
        priv, pub = _make_keypair()
        _, recv = _make_keypair()
        state = create_genesis_state({pub: 1000})
        tx = _make_signed_tx(priv, pub, recv, 10, 5)  # nonce 5, expected 0

        result = apply_transaction(tx, state)
        assert not result.success
        assert "nonce" in result.error

    def test_invalid_signature(self):
        priv, pub = _make_keypair()
        priv2, _ = _make_keypair()
        _, recv = _make_keypair()
        state = create_genesis_state({pub: 1000})

        # Forge: sign with wrong key, claim sender=pub
        tx = Transaction(sender=pub, receiver=recv, amount=10, nonce=0)
        bad_tx = sign_transaction(tx, priv2)  # wrong key signs
        # Re-create with sender=pub
        bad_tx = Transaction(sender=pub, receiver=recv, amount=10,
                             nonce=0, signature=bad_tx.signature)
        result = apply_transaction(bad_tx, state)
        assert not result.success
        assert "signature" in result.error

    def test_negative_amount(self):
        priv, pub = _make_keypair()
        _, recv = _make_keypair()
        state = create_genesis_state({pub: 1000})
        tx = _make_signed_tx(priv, pub, recv, -10, 0)

        result = apply_transaction(tx, state)
        assert not result.success
        assert "negative" in result.error

    def test_zero_amount(self):
        priv, pub = _make_keypair()
        _, recv = _make_keypair()
        state = create_genesis_state({pub: 1000})
        tx = _make_signed_tx(priv, pub, recv, 0, 0)

        result = apply_transaction(tx, state)
        assert result.success
        assert state.get_nonce(pub) == 1


class TestBlockExecution:
    def test_valid_block(self):
        priv, pub = _make_keypair()
        _, recv = _make_keypair()
        state = create_genesis_state({pub: 1000})

        tx1 = _make_signed_tx(priv, pub, recv, 100, 0)
        tx2 = _make_signed_tx(priv, pub, recv, 200, 1)

        block = Block(height=1, round=0, parent_id="genesis",
                      transactions=(tx1, tx2), proposer_id=pub)

        valid, post, root, results = execute_block(block, state)
        assert valid
        assert all(r.success for r in results)
        assert post.get_balance(pub) == 700
        assert post.get_balance(recv) == 300
        assert state.get_balance(pub) == 1000  # original not mutated

    def test_invalid_tx_stops_block(self):
        priv, pub = _make_keypair()
        _, recv = _make_keypair()
        state = create_genesis_state({pub: 100})

        tx1 = _make_signed_tx(priv, pub, recv, 50, 0)
        tx2 = _make_signed_tx(priv, pub, recv, 200, 1)  # over balance

        block = Block(height=1, round=0, parent_id="genesis",
                      transactions=(tx1, tx2), proposer_id=pub)

        valid, post, root, results = execute_block(block, state, dry_run=True)
        assert not valid
        assert state.get_balance(pub) == 100  # unchanged (dry_run)

    def test_empty_block(self):
        state = create_genesis_state({"a": 100})
        block = Block(height=1, round=0, parent_id="genesis")

        valid, post, root, results = execute_block(block, state)
        assert valid
        assert results == []
        assert post.state_root() == state.state_root()

    def test_state_root_changes_after_execution(self):
        priv, pub = _make_keypair()
        _, recv = _make_keypair()
        state = create_genesis_state({pub: 1000})
        root_before = state.state_root()

        tx = _make_signed_tx(priv, pub, recv, 500, 0)
        block = Block(height=1, round=0, parent_id="g",
                      transactions=(tx,), proposer_id=pub)

        valid, post, root_after, _ = execute_block(block, state)
        assert valid
        assert root_after != root_before
