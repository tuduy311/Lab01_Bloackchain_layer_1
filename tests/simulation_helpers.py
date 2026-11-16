"""Shared simulator setup and signed messages for integration/acceptance tests."""

from src.blockchain_simulator import BlockchainSimulator, SimulationConfig
from src.consensus.timeout import TimeoutConfig
from src.crypto import sign_block
from src.models import Block, FinalizeCertificate, Phase, Vote
from src.network import NetworkConfig


def make_simulator(num_nodes=4, seed=7, **kwargs):
    network = kwargs.pop("network", NetworkConfig(min_delay=0.001, max_delay=0.01))
    timeout = kwargs.pop("timeout", TimeoutConfig(base=0.2, multiplier=1.5, max_timeout=2))
    return BlockchainSimulator(SimulationConfig(
        num_nodes=num_nodes, seed=seed, network=network, timeout=timeout,
        gossip_interval=0.05, **kwargs,
    ))


def empty_block(sim, height=1, round_=0, state_root=None):
    proposer = sim.selector.proposer_for(height, round_)
    node = sim.nodes[proposer]
    return sign_block(Block(
        height=height, round=round_, parent_id=node.chain[node.committed_height].block_id,
        proposer_id=proposer, state_root=state_root or node.world_state.state_root(),
    ), sim.key_store.private_key(proposer))


def signed_vote(sim, voter, phase, block_id, height=1, round_=0):
    return sim.key_store.sign_vote_as(Vote(height, round_, phase, block_id, voter), voter)


def certificate(sim, block, round_=0, voters=None):
    voters = voters or sim.node_ids[:sim.selector.quorum]
    return FinalizeCertificate(block.height, round_, block.block_id, tuple(
        signed_vote(sim, voter, Phase.PRECOMMIT, block.block_id, block.height, round_)
        for voter in voters
    ))
