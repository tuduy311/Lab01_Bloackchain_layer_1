"""Tests for TV2: Models, Crypto, Execution modules."""

import pytest
import sys
import os

# Ensure the project root is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.models import (
    Block, Transaction, Vote, Phase, Message, MessageType,
    FinalizeCertificate, NIL_BLOCK_ID, genesis_block, _canonical_json,
    ValidatorSet, Polka,
)
from src.crypto import (
    generate_keypair, sign, verify, sha256_hex,
    compute_block_id, sign_block, verify_block_signature, verify_block_id,
    sign_vote, verify_vote_signature,
    sign_transaction, verify_transaction_signature,
    public_key_from_private,
    ValidatorKeyStore,
)
from src.execution import (
    AccountState, WorldState, TxResult,
    validate_transaction, apply_transaction, execute_block,
    create_genesis_state, BlockValidator, BlockValidationResult,
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


def _make_signed_block(height, round_, parent_id, proposer_priv, proposer_pub,
                       transactions=(), state_root="", timestamp=0.0):
    """Create a fully signed Block with correct block_id."""
    b = Block(
        height=height,
        round=round_,
        parent_id=parent_id,
        transactions=transactions,
        proposer_id=proposer_pub,
        timestamp=timestamp,
        state_root=state_root,
    )
    return sign_block(b, proposer_priv)


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

    def test_different_amounts_differ(self):
        tx1 = Transaction("a", "b", 10, 0)
        tx2 = Transaction("a", "b", 20, 0)
        assert tx1.canonical_bytes() != tx2.canonical_bytes()

    def test_different_nonces_differ(self):
        tx1 = Transaction("a", "b", 10, 0)
        tx2 = Transaction("a", "b", 10, 1)
        assert tx1.canonical_bytes() != tx2.canonical_bytes()


class TestBlock:
    def test_canonical_excludes_block_id_and_sig(self):
        b1 = Block(height=1, round=0, parent_id="p", block_id="", signature="")
        b2 = Block(height=1, round=0, parent_id="p", block_id="xyz", signature="sig")
        assert b1.canonical_bytes() == b2.canonical_bytes()

    def test_state_root_is_part_of_canonical(self):
        b1 = Block(height=1, round=0, parent_id="p", state_root="")
        b2 = Block(height=1, round=0, parent_id="p", state_root="abc123")
        # state_root is included in canonical content → different block_ids
        assert compute_block_id(b1) != compute_block_id(b2)

    def test_roundtrip_dict(self):
        tx = Transaction("s", "r", 10, 0, "sig")
        b = Block(height=1, round=2, parent_id="p", transactions=(tx,),
                  proposer_id="prop", timestamp=1.5, state_root="sr",
                  block_id="bid", signature="bsig")
        assert Block.from_dict(b.to_dict()) == b

    def test_state_root_survives_roundtrip(self):
        b = Block(height=1, round=0, parent_id="p", state_root="deadbeef")
        assert Block.from_dict(b.to_dict()).state_root == "deadbeef"


class TestVote:
    def test_nil_vote(self):
        v = Vote(1, 0, Phase.PREVOTE, NIL_BLOCK_ID, "voter1")
        assert v.is_nil

    def test_non_nil_vote(self):
        v = Vote(1, 0, Phase.PREVOTE, "block1", "voter1")
        assert not v.is_nil

    def test_canonical_deterministic(self):
        v1 = Vote(1, 0, Phase.PREVOTE, "block1", "v1")
        v2 = Vote(1, 0, Phase.PREVOTE, "block1", "v1")
        assert v1.canonical_bytes() == v2.canonical_bytes()

    def test_canonical_covers_all_fields(self):
        """Changing any payload field must change the canonical bytes."""
        base = Vote(1, 0, Phase.PREVOTE, "block1", "v1")
        cases = [
            Vote(2, 0, Phase.PREVOTE, "block1", "v1"),   # height differs
            Vote(1, 1, Phase.PREVOTE, "block1", "v1"),   # round differs
            Vote(1, 0, Phase.PRECOMMIT, "block1", "v1"), # phase differs
            Vote(1, 0, Phase.PREVOTE, "block2", "v1"),   # block_id differs
            Vote(1, 0, Phase.PREVOTE, "block1", "v2"),   # voter_id differs
        ]
        for other in cases:
            assert base.canonical_bytes() != other.canonical_bytes()

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

    def test_genesis_has_no_signature(self):
        g = genesis_block()
        assert g.signature == ""

    def test_genesis_empty_parent(self):
        g = genesis_block()
        assert g.parent_id == ""


class TestValidatorSet:
    def test_basic_creation(self):
        vs = ValidatorSet(("v1", "v2", "v3", "v4"), f=1)
        assert vs.n == 4
        assert vs.quorum == 3
        assert "v1" in vs

    def test_quorum_formula(self):
        # quorum = 2f+1
        assert ValidatorSet(("a", "b", "c", "d"), f=1).quorum == 3
        assert ValidatorSet(("a", "b", "c", "d", "e", "f", "g"), f=2).quorum == 5

    def test_from_public_keys(self):
        keys = [generate_keypair()[1] for _ in range(4)]
        vs = ValidatorSet.from_public_keys(keys)
        assert vs.n == 4
        assert vs.f == 1  # (4-1)//3 = 1

    def test_invalid_duplicate_validators(self):
        with pytest.raises(ValueError, match="unique"):
            ValidatorSet(("v1", "v1"), f=0)

    def test_invalid_empty(self):
        with pytest.raises(ValueError):
            ValidatorSet((), f=0)

    def test_invalid_f_too_large(self):
        with pytest.raises(ValueError, match="3f\\+1"):
            ValidatorSet(("v1", "v2"), f=1)  # need n>=4, got n=2

    def test_negative_f(self):
        with pytest.raises(ValueError, match="f must be"):
            ValidatorSet(("v1",), f=-1)

    def test_roundtrip_dict(self):
        vs = ValidatorSet(("v1", "v2", "v3", "v4"), f=1)
        assert ValidatorSet.from_dict(vs.to_dict()) == vs

    def test_contains_and_len(self):
        vs = ValidatorSet(("v1", "v2", "v3", "v4"), f=1)
        assert "v1" in vs
        assert "v5" not in vs
        assert len(vs) == 4

    def test_iteration(self):
        validators = ("v1", "v2", "v3", "v4")
        vs = ValidatorSet(validators, f=1)
        assert tuple(vs) == validators


class TestPolkaModel:
    def test_roundtrip_dict(self):
        votes = tuple(
            Vote(1, 0, Phase.PREVOTE, "bid", f"v{i}", "sig")
            for i in range(3)
        )
        polka = Polka(1, 0, "bid", votes)
        restored = Polka.from_dict(polka.to_dict())
        assert restored == polka

    def test_polka_stores_votes(self):
        votes = tuple(
            Vote(2, 1, Phase.PREVOTE, "block_xyz", f"voter_{i}")
            for i in range(3)
        )
        polka = Polka(2, 1, "block_xyz", votes)
        assert polka.height == 2
        assert polka.round == 1
        assert polka.block_id == "block_xyz"
        assert len(polka.votes) == 3


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

    def test_different_data_gives_different_sig(self):
        """Signatures are deterministic per private key but differ for different data."""
        priv, pub = generate_keypair()
        sig1 = sign(b"data1", priv)
        sig2 = sign(b"data2", priv)
        assert sig1 != sig2


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

    def test_block_id_changes_with_state_root(self):
        b1 = Block(height=1, round=0, parent_id="p", state_root="")
        b2 = Block(height=1, round=0, parent_id="p", state_root="abc")
        assert compute_block_id(b1) != compute_block_id(b2)

    def test_sign_block_preserves_state_root(self):
        priv, pub = generate_keypair()
        b = Block(height=1, round=0, parent_id="p", proposer_id=pub, state_root="sr123")
        signed = sign_block(b, priv)
        assert signed.state_root == "sr123"
        assert verify_block_id(signed)

    def test_tampered_block_fails_id_check(self):
        priv, pub = generate_keypair()
        b = Block(height=1, round=0, parent_id="p", proposer_id=pub)
        signed = sign_block(b, priv)
        # Tamper with block_id
        import dataclasses
        tampered = dataclasses.replace(signed, block_id="bad_id")
        assert not verify_block_id(tampered)


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

    def test_nil_vote_can_be_signed(self):
        priv, pub = generate_keypair()
        v = Vote(1, 0, Phase.PREVOTE, NIL_BLOCK_ID, pub)
        signed = sign_vote(v, priv)
        assert verify_vote_signature(signed, pub)

    def test_unsigned_vote_fails(self):
        _, pub = generate_keypair()
        v = Vote(1, 0, Phase.PREVOTE, "block1", pub, signature="")
        assert not verify_vote_signature(v, pub)


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


class TestValidatorKeyStore:
    def test_creation_and_lookup(self):
        store = ValidatorKeyStore(["v1", "v2", "v3", "v4"])
        assert len(store) == 4
        priv = store.private_key("v1")
        pub = store.public_key("v1")
        assert len(priv) == 64
        assert len(pub) == 64
        assert public_key_from_private(priv) == pub

    def test_public_keys_are_unique(self):
        store = ValidatorKeyStore(["v1", "v2", "v3", "v4"])
        pubs = store.public_keys
        assert len(set(pubs)) == 4

    def test_contains(self):
        store = ValidatorKeyStore(["v1", "v2"])
        assert "v1" in store
        assert "v3" not in store

    def test_unknown_validator_raises(self):
        store = ValidatorKeyStore(["v1"])
        with pytest.raises(KeyError):
            store.private_key("v99")

    def test_sign_vote_as(self):
        store = ValidatorKeyStore(["v1", "v2", "v3", "v4"])
        v = Vote(1, 0, Phase.PREVOTE, "bid", "v1")
        signed = store.sign_vote_as(v, "v1")
        assert store.verify_vote(signed, "v1")

    def test_sign_block_as(self):
        store = ValidatorKeyStore(["v1", "v2", "v3", "v4"])
        pub = store.public_key("v1")
        b = Block(height=1, round=0, parent_id="p", proposer_id=pub)
        signed = store.sign_block_as(b, "v1")
        assert verify_block_id(signed)
        assert store.verify_block(signed, "v1")

    def test_sign_transaction_as(self):
        store = ValidatorKeyStore(["v1"])
        pub = store.public_key("v1")
        tx = Transaction(sender=pub, receiver="recv", amount=100, nonce=0)
        signed = store.sign_transaction_as(tx, "v1")
        assert verify_transaction_signature(signed)

    def test_different_stores_different_keys(self):
        """Two stores with same names but independently generated keys."""
        store1 = ValidatorKeyStore(["v1"])
        store2 = ValidatorKeyStore(["v1"])
        # Keys are randomly generated, astronomically unlikely to collide
        assert store1.public_key("v1") != store2.public_key("v1")

    def test_empty_store_raises(self):
        with pytest.raises(ValueError):
            ValidatorKeyStore([])

    def test_duplicate_ids_raises(self):
        with pytest.raises(ValueError):
            ValidatorKeyStore(["v1", "v1"])


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

    def test_state_root_changes_on_mutation(self):
        ws = WorldState()
        ws.credit("a", 100)
        r1 = ws.state_root()
        ws.credit("a", 1)
        r2 = ws.state_root()
        assert r1 != r2

    def test_roundtrip_dict(self):
        ws = WorldState()
        ws.credit("a", 100)
        ws.increment_nonce("a")
        ws2 = WorldState.from_dict(ws.to_dict())
        assert ws2.get_balance("a") == 100
        assert ws2.get_nonce("a") == 1

    def test_empty_state_root_stable(self):
        """Empty world state has a fixed deterministic root."""
        r1 = WorldState().state_root()
        r2 = WorldState().state_root()
        assert r1 == r2


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

    def test_validate_does_not_mutate(self):
        priv, pub = _make_keypair()
        _, recv = _make_keypair()
        state = create_genesis_state({pub: 1000})
        tx = _make_signed_tx(priv, pub, recv, 100, 0)

        result = validate_transaction(tx, state)
        assert result.success
        assert state.get_balance(pub) == 1000  # state must NOT be mutated
        assert state.get_nonce(pub) == 0


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

    def test_dry_run_does_not_mutate_on_success(self):
        priv, pub = _make_keypair()
        _, recv = _make_keypair()
        state = create_genesis_state({pub: 1000})
        tx = _make_signed_tx(priv, pub, recv, 100, 0)
        block = Block(height=1, round=0, parent_id="g",
                      transactions=(tx,), proposer_id=pub)

        valid, post, root, _ = execute_block(block, state, dry_run=True)
        assert valid
        # dry_run still returns a modified post_state (copy)
        assert post.get_balance(pub) == 900
        # but original state is unchanged
        assert state.get_balance(pub) == 1000


# =========================================================================
# Block validation tests (TV2 §4.1 requirements)
# =========================================================================

class TestBlockValidation:
    """Test the required BlockValidator.validate(block, parent) API."""

    def _parent(self, block_id="genesis"):
        # The caller supplies a trusted parent; these unit tests use symbolic IDs.
        return Block(height=0, round=0, parent_id="", block_id=block_id)

    def _setup(self):
        priv, pub = generate_keypair()
        state = create_genesis_state({pub: 1000})
        return priv, pub, state

    def _make_valid_block(self, priv, pub, state, parent_id="genesis",
                          height=1, round_=0):
        """Build and sign a valid block with correct state_root."""
        b = Block(
            height=height, round=round_, parent_id=parent_id,
            proposer_id=pub, timestamp=0.0,
        )
        # Compute state_root by dry-running execution
        _, _, sr, _ = execute_block(b, state, dry_run=True)
        b2 = Block(
            height=b.height, round=b.round, parent_id=b.parent_id,
            transactions=b.transactions, proposer_id=b.proposer_id,
            timestamp=b.timestamp, state_root=sr,
        )
        return sign_block(b2, priv)

    def test_valid_block_passes(self):
        priv, pub, state = self._setup()
        block = self._make_valid_block(priv, pub, state)
        validator = BlockValidator(state, proposer_public_key=pub, require_state_root=True)
        assert validator.validate(block, self._parent()) is True
        assert isinstance(validator.last_result, BlockValidationResult)

    def test_wrong_block_id_fails(self):
        priv, pub, state = self._setup()
        import dataclasses
        block = self._make_valid_block(priv, pub, state)
        tampered = dataclasses.replace(block, block_id="wrong_id")
        validator = BlockValidator(state, proposer_public_key=pub)
        assert validator.validate(tampered, self._parent()) is False
        assert "block_id" in validator.last_result.error

    def test_wrong_parent_id_fails(self):
        priv, pub, state = self._setup()
        block = self._make_valid_block(priv, pub, state, parent_id="genesis")
        validator = BlockValidator(state, proposer_public_key=pub)
        assert validator.validate(block, self._parent("wrong_parent")) is False
        assert "parent_id" in validator.last_result.error

    def test_invalid_proposer_signature_fails(self):
        priv, pub, state = self._setup()
        _, pub2 = generate_keypair()
        block = self._make_valid_block(priv, pub, state)
        # Verify with the wrong public key
        validator = BlockValidator(state, proposer_public_key=pub2)
        assert validator.validate(block, self._parent()) is False
        assert "signature" in validator.last_result.error

    def test_invalid_tx_in_block_fails(self):
        priv, pub, state = self._setup()
        _, recv = generate_keypair()
        # Create a tx with wrong nonce (5 instead of 0)
        bad_tx = _make_signed_tx(priv, pub, recv, 100, 5)
        b = Block(height=1, round=0, parent_id="genesis",
                  transactions=(bad_tx,), proposer_id=pub)
        _, _, sr, _ = execute_block(b, state, dry_run=True)
        b2 = Block(height=1, round=0, parent_id="genesis",
                   transactions=(bad_tx,), proposer_id=pub, state_root="")
        signed = sign_block(b2, priv)
        validator = BlockValidator(state)
        assert validator.validate(signed, self._parent()) is False
        assert "tx[0]" in validator.last_result.error

    def test_state_root_mismatch_fails(self):
        priv, pub, state = self._setup()
        # Build block with wrong state_root
        b = Block(height=1, round=0, parent_id="genesis",
                  proposer_id=pub, state_root="wrong_state_root")
        signed = sign_block(b, priv)
        validator = BlockValidator(state, proposer_public_key=pub, require_state_root=True)
        assert validator.validate(signed, self._parent()) is False
        assert "state_root" in validator.last_result.error

    def test_valid_block_with_transactions(self):
        priv, pub, state = self._setup()
        _, recv = generate_keypair()
        tx = _make_signed_tx(priv, pub, recv, 200, 0)
        b = Block(height=1, round=0, parent_id="genesis",
                  transactions=(tx,), proposer_id=pub)
        _, _, sr, _ = execute_block(b, state, dry_run=True)
        b2 = Block(height=1, round=0, parent_id="genesis",
                   transactions=(tx,), proposer_id=pub, state_root=sr)
        signed = sign_block(b2, priv)
        validator = BlockValidator(state, proposer_public_key=pub, require_state_root=True)
        assert validator.validate(signed, self._parent()) is True
        assert validator.last_result.state_root == sr

    def test_no_signature_check_when_key_not_provided(self):
        priv, pub, state = self._setup()
        block = self._make_valid_block(priv, pub, state)
        # No proposer_public_key → signature is not checked
        validator = BlockValidator(state)
        assert validator.validate(block, self._parent()) is True

    def test_validator_records_computed_state_root(self):
        priv, pub, state = self._setup()
        _, recv = generate_keypair()
        tx = _make_signed_tx(priv, pub, recv, 100, 0)
        b = Block(height=1, round=0, parent_id="genesis",
                  transactions=(tx,), proposer_id=pub)
        signed = sign_block(b, priv)
        validator = BlockValidator(state)
        assert validator.validate(signed, self._parent()) is True
        # The returned state_root should equal what execute_block produces
        _, _, expected_root, _ = execute_block(b, state, dry_run=True)
        assert validator.last_result.state_root == expected_root

    def test_empty_block_validates(self):
        priv, pub, state = self._setup()
        b = Block(height=1, round=0, parent_id="genesis", proposer_id=pub)
        signed = sign_block(b, priv)
        validator = BlockValidator(state, proposer_public_key=pub)
        assert validator.validate(signed, self._parent()) is True

    def test_validation_is_repeatable_without_mutating_state(self):
        """Repeated validation returns a bool and never commits execution."""
        priv, pub, state = self._setup()
        block = self._make_valid_block(priv, pub, state)
        validator = BlockValidator(state, proposer_public_key=pub)
        before = state.to_dict()
        assert validator.validate(block, self._parent()) is True
        first_root = validator.last_result.state_root
        assert validator.validate(block, self._parent()) is True
        assert first_root == validator.last_result.state_root
        assert state.to_dict() == before
