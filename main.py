import random

from ca import CA
from election import Election
from voter import Voter


def main(num_voters=10):
    print("=" * 200)
    print(f"E-VOTING DEMO  ({num_voters} voters, binary vote: Yes=1 / No=0)")
    print("=" * 200)

    print("SETUP")
    print("Generating CA RSA keys")
    ca = CA(bits=512)
    print(f"CA public key n = {str(ca.pub['n'])} ({ca.pub['n'].bit_length()} bits)")

    print("Generating election authority Paillier keys")
    election = Election(ca, paillier_bits=512)
    print(f"Paillier n = {str(election.pub['n'])} ({election.pub['n'].bit_length()} bits)")

    print(f"Registering {num_voters} voters (each gets RSA keys + CA-signed cert)")
    voters = [Voter(f"voter-{i:03d}", ca) for i in range(num_voters)]
    for v in voters:
        print(f"        {v.voter_id} registered, cert signed by CA")

    print("=" * 200)
    print("VOTE")
    print("Generating random binary votes and casting encrypted ballots")
    plaintext_votes = [random.randint(0, 1) for _ in voters]
    expected_yes = sum(plaintext_votes)
    for voter, vote in zip(voters, plaintext_votes):
        ballot = voter.cast(election.pub, vote)
        ok = election.submit(ballot)
        c_short = str(ballot["ciphertext"])[:20] + "..."
        print(f"{voter.voter_id} vote={vote}, ciphertext={c_short}, accepted={ok}")
        assert ok

    print(f"Cleartext votes (sanity only): {plaintext_votes}")
    print(f"Expected Yes count: {expected_yes}")

    print("=" * 200)
    print("ATACK")
    print("voter-000 tries to vote a second time")
    replay = voters[0].cast(election.pub, 1 - plaintext_votes[0])
    accepted = election.submit(replay)
    print(f"accepted={accepted}")
    assert not accepted

    print("outsider with a forged certificate (signed by a rogue CA) tries to vote")
    rogue_ca = CA(bits=512)
    rogue = Voter("voter-999", rogue_ca)
    forged = rogue.cast(election.pub, 1)
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
    tallied = election.tally()
    no_votes = len(election.ballots) - tallied
    print(f"Decrypted sum = {tallied}  (expected {expected_yes})")
    assert tallied == expected_yes
    print("=" * 200)

    print(f"RESULT: Yes = {tallied}   No = {no_votes}   (total {len(election.ballots)})")
    print("=" * 200)


if __name__ == "__main__":
    main()
