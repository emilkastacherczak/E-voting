"""CLI demo: random multi-candidate votes, encrypted tally, attacks, audit."""

import secrets

from ca import CA
from election import Election
from voter import Voter


def short(x, n=24):
    s = str(x)
    return s if len(s) <= n else s[:n] + "..."


def main(num_voters=10, candidates=("Party A", "Party B", "Party C")):
    print("=" * 72)
    print(f"E-VOTING DEMO  ({num_voters} voters, {len(candidates)} candidates)")
    print("=" * 72)

    print("\n[setup] Generating CA RSA keys...")
    ca = CA(name="CentralCA", bits=512)
    print(f"        CA={ca.name}, n={short(ca.pub['n'])} ({ca.pub['n'].bit_length()} bits)")

    print("\n[setup] Generating election authority Paillier keys...")
    election = Election(ca, candidates=candidates, expected_voters=num_voters,
                        paillier_bits=512)
    print(f"        election_id={election.election_id}")
    print(f"        Paillier n={short(election.pub['n'])} ({election.pub['n'].bit_length()} bits)")
    print(f"        base M = {election.base_M}  (digit base for multi-candidate encoding)")

    print(f"\n[setup] Registering {num_voters} voters (RSA keys + CA-signed cert)...")
    voters = [Voter(f"voter-{i:03d}", ca) for i in range(num_voters)]
    for v in voters:
        print(f"        {v.voter_id} registered")

    print("\n[vote ] Random ballots being cast...")
    choices = [secrets.randbelow(len(candidates)) for _ in voters]
    for voter, choice in zip(voters, choices):
        ballot = voter.cast(
            election.pub, election.election_id, choice,
            num_candidates=len(candidates), base_M=election.base_M,
        )
        ok, reason = election.submit(ballot)
        print(f"        {voter.voter_id} chose '{candidates[choice]}'  "
              f"c={short(ballot['ciphertext'])}  -> {reason}")
        assert ok

    expected = {c: 0 for c in candidates}
    for choice in choices:
        expected[candidates[choice]] += 1
    print(f"\n        Cleartext counts (sanity only): {expected}")

    print("\n[atk  ] voter-000 tries to vote a second time (double-vote)...")
    replay = voters[0].cast(
        election.pub, election.election_id, (choices[0] + 1) % len(candidates),
        num_candidates=len(candidates), base_M=election.base_M,
    )
    ok, reason = election.submit(replay)
    print(f"        accepted={ok}  reason={reason!r}")
    assert not ok

    print("\n[atk  ] outsider with cert signed by a rogue CA tries to vote...")
    rogue_ca = CA(name="RogueCA", bits=512)
    rogue = Voter("voter-999", rogue_ca)
    forged = rogue.cast(
        election.pub, election.election_id, 0,
        num_candidates=len(candidates), base_M=election.base_M,
    )
    ok, reason = election.submit(forged)
    print(f"        accepted={ok}  reason={reason!r}")
    assert not ok

    print("\n[atk  ] attacker tampers with a ciphertext after submission...")
    target = list(election.box.chain)[0]
    original_ct = target["ciphertext"]
    target["ciphertext"] = (target["ciphertext"] + 1) % (election.pub["n"] ** 2)
    ok_chain, bad_idx = election.box.verify_integrity()
    print(f"        chain integrity ok={ok_chain}  first_bad_index={bad_idx}")
    target["ciphertext"] = original_ct  # restore so the tally is correct
    assert not ok_chain

    print("\n[verify] Every voter re-encrypts with saved randomness and checks ballot box...")
    for voter in voters:
        stored = election.stored_ciphertext(voter.voter_id)
        assert voter.verify_recorded(election.pub, stored)
    print(f"        all {num_voters} voters verified their ballots ✓")

    print("\n[tally] Homomorphically multiplying ciphertexts, then a single decryption...")
    election.close()
    counts, encrypted_sum, plain_sum = election.tally()
    print(f"        encrypted aggregate = {short(encrypted_sum)}")
    print(f"        decrypted base-{election.base_M} integer = {plain_sum}")
    print(f"        decoded counts: {counts}")
    assert counts == expected

    print("\n" + "=" * 72)
    print("RESULT")
    total = sum(counts.values())
    for name, n in counts.items():
        bar = "#" * (40 * n // max(total, 1))
        print(f"  {name:>20}  {n:3d}  {bar}")
    print("=" * 72)


if __name__ == "__main__":
    main()
