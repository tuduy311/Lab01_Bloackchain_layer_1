"""Tests for TV3: scheduler, network, proposer selection and round timeouts.

Covers the acceptance criteria of the TV3 assignment:
* reproducible network faults driven by a seed (delay / drop / duplicate /
  reorder),
* outbound rate limiting and temporary peer block/unblock,
* header-before-body propagation,
* deterministic proposer per (height, round),
* round timeouts that fire exactly once and back off per round,
* a network configuration with at least 8 nodes (Lab01 §6).
"""

import os
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.scheduler import Scheduler, to_ticks, to_seconds
from src.network import (
    KIND_BODY,
    KIND_BODY_REQUEST,
    KIND_HEADER,
    MIN_NODES,
    DropReason,
    Network,
    NetworkConfig,
    NetworkEnvelope,
    NetworkEventType,
    PeerBlockList,
    RateLimitPolicy,
    SendStatus,
    TokenBucket,
    DeterministicRandom,
    derive_seed,
    hash_to_unit,
)
from src.consensus.proposer import ProposerSelector
from src.consensus.timeout import TimeoutConfig, TimeoutManager


# =========================================================================
# Helpers
# =========================================================================

NODE_IDS = [f"node_{i + 1}" for i in range(MIN_NODES)]


def make_network(seed=0, nodes=None, **config_kwargs):
    """Build a network where every node logs the envelopes it receives."""
    scheduler = Scheduler()
    nodes = list(nodes or NODE_IDS)
    config = NetworkConfig(
        num_nodes=len(nodes),
        seed=seed,
        **config_kwargs,
    )
    net = Network(scheduler, config, nodes)
    inbox = {n: [] for n in nodes}

    def handler(node_id, envelope):
        inbox[node_id].append(envelope)

    for node_id in nodes:
        net.set_receiver(node_id, handler)
    return scheduler, net, inbox


def events_of(net, event_type):
    return [e for e in net.events if e.event == event_type.value]


def statuses(net):
    return [e.event for e in net.events]


# =========================================================================
# Scheduler
# =========================================================================

class TestScheduler:
    def test_events_run_in_time_order(self):
        sched = Scheduler()
        log = []
        sched.schedule_after(0.3, log.append, "c")
        sched.schedule_after(0.1, log.append, "a")
        sched.schedule_after(0.2, log.append, "b")
        assert sched.run() == 3
        assert log == ["a", "b", "c"]
        assert sched.now == pytest.approx(0.3)

    def test_same_time_is_fifo(self):
        sched = Scheduler()
        log = []
        for i in range(5):
            sched.schedule_after(0.5, log.append, i)
        sched.run()
        assert log == [0, 1, 2, 3, 4]

    def test_reschedule_from_callback_keeps_order(self):
        sched = Scheduler()
        log = []

        def first():
            log.append("first")
            sched.schedule_after(0.0, log.append, "scheduled-by-first")

        sched.schedule_after(0.0, first)
        sched.schedule_after(0.0, log.append, "second")
        sched.run()
        assert log == ["first", "second", "scheduled-by-first"]

    def test_cancel_skips_callback(self):
        sched = Scheduler()
        log = []
        handle = sched.schedule_after(0.1, log.append, "cancelled")
        sched.schedule_after(0.2, log.append, "kept")
        assert sched.cancel(handle) is True
        assert sched.cancel(handle) is False          # idempotent
        sched.run()
        assert log == ["kept"]
        assert sched.processed_events == 1

    def test_run_until_stops_at_boundary(self):
        sched = Scheduler()
        log = []
        for i in range(1, 5):
            sched.schedule_after(i * 0.1, log.append, i)
        assert sched.run_until(0.2) == 2
        assert log == [1, 2]
        assert sched.now == pytest.approx(0.2)

    def test_tick_arithmetic_is_exact(self):
        # 0.1 + 0.2 != 0.3 in binary floating point; ticks must not care.
        sched = Scheduler()
        seen = []

        def at_second_event():
            seen.append(sched.now)

        sched.schedule_after(
            0.1, lambda: sched.schedule_after(0.2, at_second_event)
        )
        sched.run()
        assert to_ticks(seen[0]) == to_ticks(0.3)

    def test_peek_time_and_len(self):
        sched = Scheduler()
        assert sched.peek_time() is None and len(sched) == 0
        sched.schedule_after(0.25, lambda: None)
        assert sched.peek_time() == pytest.approx(0.25)
        assert len(sched) == 1
        sched.run()
        assert sched.peek_time() is None and len(sched) == 0

    def test_past_time_is_clamped_to_now(self):
        sched = Scheduler(start_time=1.0)
        sched.run_until(2.0)
        sched.schedule_at(0.5, lambda: None)
        assert sched.peek_time() == pytest.approx(2.0)

    def test_invalid_time_rejected(self):
        sched = Scheduler()
        with pytest.raises(ValueError):
            sched.schedule_at(float("nan"), lambda: None)
        with pytest.raises(ValueError):
            sched.schedule_after(-0.1, lambda: None)

    def test_ticks_roundtrip(self):
        assert to_seconds(to_ticks(1.2345)) == pytest.approx(1.2345)


# =========================================================================
# Deterministic RNG
# =========================================================================

class TestDeterministicRandom:
    def test_derived_seed_is_stable_and_distinct(self):
        assert derive_seed(7, "a") == derive_seed(7, "a")
        assert derive_seed(7, "a") != derive_seed(7, "b")
        assert derive_seed(7, "a") != derive_seed(8, "a")

    def test_same_stream_reproduces(self):
        first = DeterministicRandom(42, "link:x->y")
        second = DeterministicRandom(42, "link:x->y")
        assert [first.random() for _ in range(5)] == [second.random() for _ in range(5)]

    def test_streams_are_independent(self):
        a = DeterministicRandom(42, "link:a")
        b = DeterministicRandom(42, "link:b")
        assert [a.random() for _ in range(5)] != [b.random() for _ in range(5)]

    def test_shuffled_is_a_deterministic_permutation(self):
        items = list("abcdef")
        assert DeterministicRandom(1).shuffled(items) == DeterministicRandom(1).shuffled(items)
        shuffled = DeterministicRandom(1).shuffled(items)
        assert sorted(shuffled) == sorted(items)
        assert items == list("abcdef")  # input untouched

    def test_chance_bounds(self):
        rng = DeterministicRandom(3)
        assert rng.chance(0.0) is False
        assert rng.chance(1.0) is True

    def test_hash_to_unit_is_in_range(self):
        for i in range(20):
            value = hash_to_unit(1, i)
            assert 0.0 <= value < 1.0
        assert hash_to_unit(1, 2) == hash_to_unit(1, 2)


# =========================================================================
# Proposer selection
# =========================================================================

class TestProposerSelector:
    def setup_method(self):
        self.validators = ("A", "B", "C", "D")
        self.selector = ProposerSelector(self.validators, seed=0)

    def test_is_deterministic_across_instances(self):
        other = ProposerSelector(self.validators, seed=0)
        for height in range(5):
            for rnd in range(4):
                assert self.selector.proposer_for(height, rnd) == other.proposer_for(height, rnd)
        assert list(self.selector) == list(other)

    def test_round_rotation_uses_every_validator(self):
        leaders = self.selector.schedule(height=3, rounds=4)
        assert len(set(leaders)) == 4
        assert set(leaders) == set(self.validators)

    def test_consecutive_rounds_have_different_proposers(self):
        for height in range(4):
            for rnd in range(3):
                assert self.selector.proposer_for(height, rnd) != self.selector.proposer_for(
                    height, rnd + 1
                )

    def test_height_changes_leader(self):
        assert self.selector.proposer_for(1, 0) != self.selector.proposer_for(2, 0)

    def test_is_proposer(self):
        leader = self.selector.proposer_for(7, 2)
        assert self.selector.is_proposer(leader, 7, 2)
        assert not any(
            self.selector.is_proposer(other, 7, 2)
            for other in self.validators
            if other != leader
        )

    def test_seed_changes_the_ring(self):
        rings = {
            ProposerSelector(self.validators, seed=seed).engine_order
            for seed in range(6)
        }
        assert len(rings) > 1
        for ring in rings:
            assert set(ring) == set(self.validators)

    @pytest.mark.parametrize("size,expected", [(4, 3), (7, 5), (8, 5), (10, 7)])
    def test_quorum_matches_2f_1(self, size, expected):
        selector = ProposerSelector(tuple(f"v{i}" for i in range(size)))
        assert selector.quorum == expected

    def test_invalid_configuration(self):
        with pytest.raises(ValueError):
            ProposerSelector(())
        with pytest.raises(ValueError):
            ProposerSelector(("A", "A"))
        with pytest.raises(ValueError):
            ProposerSelector(("A", ""))

    def test_negative_slot_rejected(self):
        with pytest.raises(ValueError):
            self.selector.proposer_for(-1, 0)
        with pytest.raises(ValueError):
            self.selector.proposer_for(0, -1)


# =========================================================================
# Round timeouts
# =========================================================================

class TestTimeoutConfig:
    def test_exponential_backoff(self):
        config = TimeoutConfig(base=1.0, multiplier=2.0, max_timeout=100.0)
        assert config.duration(0, 0) == pytest.approx(1.0)
        assert config.duration(0, 1) == pytest.approx(2.0)
        assert config.duration(0, 2) == pytest.approx(4.0)

    def test_capped_at_max_timeout(self):
        config = TimeoutConfig(base=1.0, multiplier=2.0, max_timeout=5.0)
        assert config.duration(0, 10) == pytest.approx(5.0)

    def test_jitter_is_deterministic_and_bounded(self):
        config = TimeoutConfig(base=1.0, multiplier=1.0, jitter=0.2, seed=5)
        first = config.duration(3, 1)
        assert first == pytest.approx(config.duration(3, 1))
        assert 0.8 <= first <= 1.2
        # a different slot gets a different (still deterministic) offset
        assert config.duration(3, 2) != pytest.approx(first) or config.jitter == 0

    def test_validation(self):
        with pytest.raises(ValueError):
            TimeoutConfig(base=0.0).validate()
        with pytest.raises(ValueError):
            TimeoutConfig(multiplier=0.5).validate()
        with pytest.raises(ValueError):
            TimeoutConfig(jitter=1.5).validate()


class TestTimeoutManager:
    def test_fires_at_deadline(self):
        sched = Scheduler()
        fired = []
        manager = TimeoutManager(sched, lambda h, r: fired.append((h, r)),
                                 TimeoutConfig(base=1.0))
        manager.start(0, 0)
        sched.run_until(0.999)
        assert fired == []
        sched.run_until(1.0)
        assert fired == [(0, 0)]
        assert manager.fired_at(0, 0) == pytest.approx(1.0)

    def test_fires_exactly_once_per_slot(self):
        sched = Scheduler()
        fired = []
        manager = TimeoutManager(sched, lambda h, r: fired.append((h, r)),
                                 TimeoutConfig(base=1.0, multiplier=1.0))
        manager.start(2, 0)
        sched.run()
        assert fired == [(2, 0)]
        manager.start(2, 0)          # re-entering a finished round must not re-arm
        sched.run()
        assert fired == [(2, 0)]
        assert manager.has_fired(2, 0)

    def test_advancing_round_cancels_previous_timer(self):
        sched = Scheduler()
        fired = []
        manager = TimeoutManager(sched, lambda h, r: fired.append((h, r)),
                                 TimeoutConfig(base=1.0, multiplier=2.0))
        manager.start(0, 0)
        sched.run_until(0.5)
        manager.start(0, 1)          # leave round 0 early
        sched.run()
        assert fired == [(0, 1)]
        assert manager.fired_at(0, 1) == pytest.approx(2.5)
        assert not manager.has_fired(0, 0)

    def test_stop_prevents_firing(self):
        sched = Scheduler()
        fired = []
        manager = TimeoutManager(sched, lambda h, r: fired.append((h, r)))
        manager.start(0, 0)
        assert manager.stop() is True
        sched.run()
        assert fired == []
        assert manager.deadline is None

    def test_stale_timer_is_ignored(self):
        sched = Scheduler()
        fired = []
        manager = TimeoutManager(sched, lambda h, r: fired.append((h, r)),
                                 TimeoutConfig(base=1.0, multiplier=1.0))
        manager.start(0, 0)
        sched.run_until(0.2)
        manager.stop()
        manager.start(0, 1)
        sched.run()
        assert fired == [(0, 1)]

    def test_deadline_reflects_config(self):
        sched = Scheduler()
        manager = TimeoutManager(sched, lambda h, r: None, TimeoutConfig(base=2.0))
        manager.start(1, 0)
        assert manager.deadline == pytest.approx(2.0)
        assert manager.active_slot == (1, 0)

    def test_round_backoff_through_fired_slots(self):
        sched = Scheduler()
        fired = []
        manager = TimeoutManager(sched, None, TimeoutConfig(base=1.0, multiplier=2.0))

        def on_timeout(height, rnd):
            fired.append((height, rnd))
            manager.start(height, rnd + 1)

        manager.set_callback(on_timeout)
        manager.start(0, 0)
        sched.run_until(1.0 + 2.0 + 4.0)
        assert fired == [(0, 0), (0, 1), (0, 2)]
        assert manager.fired_rounds(0) == (0, 1, 2)


# =========================================================================
# Rate limiting primitives
# =========================================================================

class TestTokenBucket:
    def test_burst_then_refill(self):
        bucket = TokenBucket(capacity=2, refill_per_second=1.0)
        assert bucket.allow(0.0) and bucket.allow(0.0)
        assert not bucket.allow(0.0)
        assert bucket.allow(1.0)              # one token refilled
        assert not bucket.allow(1.0)

    def test_available_never_exceeds_capacity(self):
        bucket = TokenBucket(capacity=3, refill_per_second=10.0)
        assert bucket.available(100.0) == pytest.approx(3.0)

    def test_invalid_parameters(self):
        with pytest.raises(ValueError):
            TokenBucket(capacity=0, refill_per_second=1.0)
        with pytest.raises(ValueError):
            TokenBucket(capacity=1, refill_per_second=0.0)


class TestPeerBlockList:
    def test_block_expires(self):
        blocks = PeerBlockList("node_1")
        blocks.block("node_2", since=0.0, until=2.0, reason="overactive")
        assert blocks.is_blocked("node_2", 1.0)
        assert not blocks.is_blocked("node_2", 2.0)
        assert blocks.get("node_2") is not None   # removal is the network's job
        assert blocks.unblock("node_2") is not None
        assert blocks.unblock("node_2") is None


# =========================================================================
# Network configuration
# =========================================================================

class TestNetworkConfig:
    def test_default_supports_lab_topology(self):
        config = NetworkConfig()
        assert config.num_nodes == MIN_NODES == 8
        assert config.validate(strict=True) == []

    def test_strict_mode_requires_eight_nodes(self):
        problems = NetworkConfig(num_nodes=4).validate(strict=True)
        assert problems and "8" in problems[0]
        assert NetworkConfig(num_nodes=4).validate() == []

    def test_invalid_parameters(self):
        assert NetworkConfig(min_delay=0.2, max_delay=0.1).validate()
        assert NetworkConfig(drop_rate=1.5).validate()
        assert NetworkConfig(duplicate_rate=-0.1).validate()
        assert NetworkConfig(rate_limit=RateLimitPolicy(capacity=0)).validate()
        with pytest.raises(ValueError):
            NetworkConfig(min_delay=0.2, max_delay=0.1).require_valid()

    def test_network_rejects_invalid_config(self):
        with pytest.raises(ValueError):
            Network(Scheduler(), NetworkConfig(max_delay=-1.0), ["a", "b"])

    def test_dict_roundtrip(self):
        config = NetworkConfig(
            num_nodes=10, seed=5, drop_rate=0.2, duplicate_rate=0.1,
            stabilize_at=3.0, rate_limit=RateLimitPolicy(capacity=8),
        )
        clone = NetworkConfig.from_dict(config.to_dict())
        assert clone == config
        assert clone.validate(strict=True) == []

    def test_from_dict_ignores_unknown_keys(self):
        config = NetworkConfig.from_dict({"num_nodes": 8, "unknown_key": 1})
        assert config.num_nodes == 8
        assert config.validate(strict=True) == []

    def test_network_rejects_duplicate_nodes(self):
        with pytest.raises(ValueError):
            Network(Scheduler(), NetworkConfig(), ["a", "a"])


# =========================================================================
# Network: delay, drop, duplicate, reorder
# =========================================================================

class TestNetworkTransport:
    def test_message_is_delivered_after_delay(self):
        sched, net, inbox = make_network(min_delay=0.02, max_delay=0.04)
        assert net.send("node_1", "node_2", "hello", kind="PREVOTE", height=3) is SendStatus.QUEUED
        assert inbox["node_2"] == []
        sched.run()
        assert len(inbox["node_2"]) == 1
        envelope = inbox["node_2"][0]
        assert envelope.payload == "hello"
        assert 0.02 <= envelope.deliver_time - envelope.send_time <= 0.04
        assert envelope.height == 3

    def test_delay_is_reproducible_for_a_seed(self):
        def run(seed):
            sched, net, inbox = make_network(seed=seed, min_delay=0.0, max_delay=1.0)
            for i in range(10):
                net.send("node_1", "node_2", i)
            sched.run()
            return [e.deliver_time for e in inbox["node_2"]]

        assert run(seed=11) == run(seed=11)
        assert run(seed=11) != run(seed=12)

    def test_reordering_happens_with_random_delays(self):
        sched, net, inbox = make_network(seed=1, min_delay=0.0, max_delay=1.0)
        for i in range(10):
            net.send("node_1", "node_2", i)
        sched.run()
        arrival_order = [e.payload for e in inbox["node_2"]]
        assert sorted(arrival_order) == list(range(10))   # nothing lost
        assert arrival_order != sorted(arrival_order)     # but reordered

    def test_total_drop(self):
        sched, net, inbox = make_network(drop_rate=1.0)
        net.send("node_1", "node_2", "lost")
        sched.run()
        assert inbox["node_2"] == []
        assert net.counters["dropped"] == 1
        assert events_of(net, NetworkEventType.DROP)[0].reason == DropReason.RANDOM

    def test_duplicates_are_created(self):
        sched, net, inbox = make_network(duplicate_rate=1.0)
        net.send("node_1", "node_2", "echo")
        sched.run()
        assert len(inbox["node_2"]) == 2
        assert {e.is_duplicate for e in inbox["node_2"]} == {False, True}
        assert net.counters["duplicates_created"] == 1

    def test_broadcast_reaches_every_peer(self):
        sched, net, inbox = make_network()
        results = net.broadcast("node_1", "header", kind="PROPOSAL", height=1)
        sched.run()
        assert set(results) == set(NODE_IDS) - {"node_1"}
        assert all(status is SendStatus.QUEUED for status in results.values())
        assert all(len(inbox[n]) == 1 for n in NODE_IDS[1:])
        assert inbox["node_1"] == []

    def test_self_send_is_ignored(self):
        sched, net, _ = make_network()
        assert net.send("node_1", "node_1", "x") is SendStatus.SELF
        assert net.send("node_1", "ghost", "x") is SendStatus.UNKNOWN_NODE

    def test_height_is_taken_from_payload(self):
        sched, net, _ = make_network()
        net.send("node_1", "node_2", SimpleNamespace(height=9))
        send_event = events_of(net, NetworkEventType.SEND)[0]
        assert send_event.height == 9

    def test_determinism_after_stabilization(self):
        sched, net, inbox = make_network(
            seed=4, drop_rate=1.0, duplicate_rate=1.0, stabilize_at=5.0
        )
        net.send("node_1", "node_2", "before")
        sched.run_until(5.0)
        assert inbox["node_2"] == []          # pre-synchrony: dropped

        net.send("node_1", "node_2", "after")
        sched.run()
        assert [e.payload for e in inbox["node_2"]] == ["after"]

    def test_full_event_log_is_reproducible(self):
        def run(seed):
            sched, net, _ = make_network(
                seed=seed, drop_rate=0.1, duplicate_rate=0.1,
                min_delay=0.0, max_delay=0.02,
            )
            for i in range(30):
                net.broadcast("node_1", f"m{i}", kind="PREVOTE", height=i % 3)
            sched.run()
            return [e.to_dict() for e in net.events], net.scheduler.now

        logs_a, now_a = run(seed=99)
        logs_b, now_b = run(seed=99)
        logs_c, _ = run(seed=100)
        assert logs_a == logs_b
        assert now_a == now_b
        assert logs_a != logs_c

    def test_event_log_has_required_fields(self):
        sched, net, _ = make_network()
        net.send("node_1", "node_2", "x", kind="PREVOTE", height=2)
        sched.run()
        record = net.events[0].to_dict()
        for key in ("time", "node_id", "event", "kind", "height"):
            assert key in record
        assert record["event"] == NetworkEventType.SEND.value
        assert record["node_id"] == "node_1"
        assert record["height"] == 2


# =========================================================================
# Network: rate limiting and peer blocking
# =========================================================================

class TestRateLimiting:
    def test_unused_link_tokens_are_bounded(self):
        sched, net, _ = make_network()
        bucket = net._outbound[("node_1", "node_2")]
        assert bucket.available(1000.0) <= bucket.capacity

    def test_outbound_rate_limit_drops_excess(self):
        policy = RateLimitPolicy(capacity=3, refill_per_second=1.0,
                                 inbound_capacity=1000)
        sched, net, inbox = make_network(rate_limit=policy)
        outcomes = [net.send("node_1", "node_2", i) for i in range(5)]
        assert outcomes[:3] == [SendStatus.QUEUED] * 3
        assert outcomes[3:] == [SendStatus.RATE_LIMITED] * 2
        sched.run()
        assert len(inbox["node_2"]) == 3
        reasons = [e.reason for e in events_of(net, NetworkEventType.DROP)]
        assert reasons == [DropReason.RATE_LIMITED] * 2

    def test_overactive_peer_is_blocked_then_unblocked(self):
        policy = RateLimitPolicy(capacity=100, refill_per_second=100.0,
                                 inbound_capacity=3, inbound_window=1.0,
                                 peer_block_duration=2.0)
        sched, net, inbox = make_network(rate_limit=policy)
        outcomes = [net.send("node_1", "node_2", i) for i in range(5)]
        assert outcomes[3] is SendStatus.BLOCKED        # 4th message trips the limit
        assert net.is_blocked("node_2", "node_1")

        sched.run_until(1.5)
        assert net.send("node_1", "node_2", "while-blocked") is SendStatus.BLOCKED

        sched.run_until(2.0)                            # block expires at t=2
        assert not net.is_blocked("node_2", "node_1")
        assert net.send("node_1", "node_2", "after") is SendStatus.QUEUED
        sched.run()

        block_events = events_of(net, NetworkEventType.BLOCK)
        unblock_events = events_of(net, NetworkEventType.UNBLOCK)
        assert len(block_events) == 1 and len(unblock_events) == 1
        assert block_events[0].reason == DropReason.INBOUND_OVERACTIVE
        assert unblock_events[0].reason == "expired"
        assert net.is_blocked("node_3", "node_1") is False

    def test_manual_block_and_unblock(self):
        sched, net, inbox = make_network()
        net.block_peer("node_2", "node_1", duration=5.0, reason="manual")
        assert net.send("node_1", "node_2", "x") is SendStatus.BLOCKED
        assert net.blocked_peers("node_2") == ("node_1",)
        assert net.unblock_peer("node_2", "node_1") is True
        assert net.send("node_1", "node_2", "x") is SendStatus.QUEUED
        sched.run_until(10.0)
        assert [e.payload for e in inbox["node_2"]] == ["x"]

    def test_in_flight_message_is_dropped_when_peer_blocks(self):
        sched, net, inbox = make_network(min_delay=0.5, max_delay=0.5)
        net.send("node_1", "node_2", "in-flight")
        net.block_peer("node_2", "node_1", duration=5.0)
        sched.run_until(1.0)
        assert inbox["node_2"] == []
        assert events_of(net, NetworkEventType.DROP)[0].reason == DropReason.PEER_BLOCKED


# =========================================================================
# Network: header-before-body
# =========================================================================

class TestHeaderBeforeBody:
    def test_body_without_header_is_rejected(self):
        sched, net, inbox = make_network()
        assert net.send_body("node_1", "node_2", "h1", {"txs": []}) is SendStatus.HEADER_NOT_ACCEPTED
        sched.run()
        assert inbox["node_2"] == []
        assert events_of(net, NetworkEventType.DROP)[0].reason == DropReason.HEADER_NOT_ACCEPTED

    def test_body_requires_header_acceptance(self):
        sched, net, inbox = make_network()
        net.announce_header("node_1", "h1", {"header": 1})
        sched.run()

        assert net.gate.has_header("node_2", "h1")
        assert net.gate.status("node_2", "h1") == "ANNOUNCED"
        assert net.send_body("node_1", "node_2", "h1", {"txs": []}) is SendStatus.HEADER_NOT_ACCEPTED

        assert net.accept_header("node_2", "h1") is True
        assert net.gate.status("node_2", "h1") == "ACCEPTED"
        assert net.send_body("node_1", "node_2", "h1", {"txs": []}) is SendStatus.QUEUED
        sched.run()

        assert [e.kind for e in inbox["node_2"]] == [KIND_HEADER, KIND_BODY]
        assert net.gate.status("node_2", "h1") == "BODY_DELIVERED"
        assert events_of(net, NetworkEventType.HEADER_ACCEPT)[0].node_id == "node_2"

    def test_accept_unknown_header_fails(self):
        sched, net, _ = make_network()
        assert net.accept_header("node_2", "ghost") is False

    def test_body_request_requires_seen_header(self):
        sched, net, inbox = make_network()
        assert net.request_body("node_2", "node_1", "h1") is SendStatus.HEADER_NOT_SEEN
        net.announce_header("node_1", "h1", {"header": 1})
        sched.run()
        assert net.request_body("node_2", "node_1", "h1") is SendStatus.QUEUED
        sched.run()
        assert [e.kind for e in inbox["node_1"]] == [KIND_BODY_REQUEST]

    def test_duplicate_body_is_marked(self):
        sched, net, inbox = make_network()
        net.announce_header("node_1", "h1", {"header": 1})
        sched.run()
        net.accept_header("node_2", "h1")
        net.send_body("node_1", "node_2", "h1", {"txs": []})
        net.send_body("node_1", "node_2", "h1", {"txs": []})
        sched.run()
        deliver_events = events_of(net, NetworkEventType.DELIVER)
        body_events = [e for e in deliver_events if e.kind == KIND_BODY]
        assert [e.reason for e in body_events] == ["", DropReason.DUP_BODY]
        assert len(inbox["node_2"]) == 3           # header + body + duplicate body

    def test_packet_injected_before_header_is_dropped_at_receiver(self):
        # Models a body that reaches the receiver before the header: the gate
        # must reject it at delivery time, not only at send time.
        sched, net, inbox = make_network()
        injected = NetworkEnvelope(
            envelope_id="env-injected",
            kind=KIND_BODY,
            sender_id="node_1",
            recipient_id="node_2",
            payload={"txs": []},
            send_time=0.0,
            deliver_time=0.0,
            header_id="h-early",
        )
        net._deliver(injected)
        assert inbox["node_2"] == []
        assert events_of(net, NetworkEventType.DROP)[0].reason == DropReason.HEADER_NOT_ACCEPTED

    def test_full_handshake_across_eight_nodes(self):
        scheduler = Scheduler()
        net = Network(
            scheduler,
            NetworkConfig(num_nodes=MIN_NODES, seed=7, min_delay=0.01, max_delay=0.03),
            NODE_IDS,
        )
        received = {node: [] for node in NODE_IDS}
        proposer = NODE_IDS[0]
        header_id = "h-block-1"

        def handler(node_id, envelope):
            received[node_id].append(envelope)
            if node_id == proposer:
                if envelope.kind == KIND_BODY_REQUEST:
                    net.send_body(
                        proposer, envelope.sender_id, envelope.header_id,
                        {"txs": ["tx1"]}, height=envelope.height,
                    )
            elif envelope.kind == KIND_HEADER:
                assert net.accept_header(node_id, envelope.header_id)
                net.request_body(node_id, proposer, envelope.header_id, height=envelope.height)

        for node in NODE_IDS:
            net.set_receiver(node, handler)

        net.announce_header(proposer, header_id, {"header": 1}, height=1)
        scheduler.run()

        for peer in NODE_IDS[1:]:
            assert net.gate.is_body_delivered(peer, header_id), peer
            kinds = [e.kind for e in received[peer]]
            assert kinds == [KIND_HEADER, KIND_BODY]
        assert [e.kind for e in received[proposer]] == [KIND_BODY_REQUEST] * (MIN_NODES - 1)
        assert net.counters["header_rejected"] == 0
