# Configuration

`default.json` is the runnable baseline. Scenario files override network,
timeout, seed, event cap, and fault settings. Network settings match across all
validators in a run.

Main fields:

- `num_nodes`, `seed`, `chain_id`, `target_height`, `max_events`
- `network`: delay, loss, duplication, stabilization time and rate limit
- `timeout`: base, exponential multiplier, cap and deterministic jitter
- `silent_slots`: `[height, round]` slots where the selected proposer is silent
- `equivocate_proposer_round0`: make the round-0 proposer send two valid values
- `prestart_gossip`: propagate the demo transaction before consensus starts

See `../README.md` for invocation details.
