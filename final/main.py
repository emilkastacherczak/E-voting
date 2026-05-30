import argparse
import random

from ca import CA
from election import Election
from voter import Voter


def main(num_voters=10, candidates=("Party A", "Party B", "Party C")):
    print("=" * 200)
    print(f"E-VOTING DEMO  ({num_voters} voters, {len(candidates)} candidates)")


    print("=" * 200)
    print("SETUP")


    print("Generating CA RSA keys")
    ca = CA(bits=512)
    print(f"CA public key n = {str(ca.pub['n'])} ({ca.pub['n'].bit_length()} bits)")

    print("Generating election authority Paillier keys")
    election = Election(ca, candidates=candidates, expected_voters=num_voters, paillier_bits=512)
    print(f"Paillier n = {str(election.pub['n'])} ({election.pub['n'].bit_length()} bits)")
    print(f"base M = {election.base_M}  (vote for candidate i encrypts M^i)")

    print(f"Registering {num_voters} voters (each gets RSA keys + CA-signed cert)")
    voters = [Voter(f"voter-{i:03d}", ca) for i in range(num_voters)]
    for v in voters:
        print(f"{v.voter_id} registered, cert signed by CA")


    print("=" * 200)
    print("VOTE")


    print("Generating random votes and casting encrypted ballots")
    choices = [random.randrange(len(candidates)) for _ in voters]
    expected = {c: 0 for c in candidates}
    for choice in choices:
        expected[candidates[choice]] += 1

    for voter, choice in zip(voters, choices):
        ballot = voter.cast(election.pub, choice, len(candidates), election.base_M)
        ok = election.submit(ballot)
        c_short = str(ballot["ciphertext"])[:20] + "..."
        print(f"{voter.voter_id} choice={candidates[choice]}, ciphertext={c_short}, accepted={ok}")
        assert ok

    print(f"Cleartext choices (sanity only): {[candidates[c] for c in choices]}")
    print(f"Expected counts: {expected}")


    print("=" * 200)
    print("ATACK")


    print("voter-000 tries to vote a second time")
    replay = voters[0].cast(election.pub, (choices[0] + 1) % len(candidates),
                            len(candidates), election.base_M)
    accepted = election.submit(replay)
    print(f"accepted={accepted}")
    assert not accepted

    print("outsider with a forged certificate (signed by a rogue CA) tries to vote")
    rogue_ca = CA(bits=512)
    rogue = Voter("voter-999", rogue_ca)
    forged = rogue.cast(election.pub, 0, len(candidates), election.base_M)
    accepted = election.submit(forged)
    print(f"accepted={accepted}")
    assert not accepted


    print("=" * 200)
    print("VERIFICATION")


    print("Each voter re-encrypts with their saved randomness and checks the stored ballot...")
    for voter in voters:
        stored = election.stored_ciphertext(voter.voter_id)
        ok = voter.verify_recorded(election.pub, stored)
        print(f"{voter.voter_id} verifies own ballot: {ok}")
        assert ok


    print("=" * 200)
    print("SUMMARY")


    print("Homomorphically multiplying all ciphertexts and decrypting once")
    counts = election.tally()
    print(f"Decoded counts: {counts}")
    assert counts == expected


    print("=" * 200)
    print(f"RESULT: {counts}   (total {len(election.ballots)})")
    print("=" * 200)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--voters", type=int, default=10)
    parser.add_argument("--candidates", nargs="+", default=["Party A", "Party B", "Party C"])
    args = parser.parse_args()
    main(args.voters, args.candidates)