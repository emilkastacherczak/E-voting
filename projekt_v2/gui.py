"""Tkinter GUI for the e-voting demo.

Tabs:
  1. Setup       - generate CA keys, choose candidates, init election
  2. Voters      - register voters one-by-one or in bulk
  3. Vote        - cast ballots manually or via random generator
  4. Verify      - voter re-encrypts with saved receipt to audit ballot box
  5. Attacks     - one-click demos of double-vote, rogue CA, tampering, id spoof
  6. Tally       - close election, homomorphic sum, decode counts, bar chart
  7. Ballot Box  - inspect the hash-chain, run integrity check, demo tampering

Run:  python3 gui.py
"""

import secrets
import tkinter as tk
from tkinter import ttk, messagebox

from ca import CA
from election import Election, PHASE_CLOSED, PHASE_VOTING
from voter import Voter


# ----- visual constants ---------------------------------------------------- #

SHORT_LEN = 28
COLOR_OK = "#1f7a3a"
COLOR_BAD = "#a8302a"
COLOR_MUTED = "#666"
COLOR_BAR = "#2c6dd6"
COLOR_BAR_TEXT = "#ffffff"
COLOR_HEADER_BG = "#eef2f7"
MONOSPACE = ("Courier", 10)
HEADER_FONT = ("TkDefaultFont", 11, "bold")


def short(x, n=SHORT_LEN):
    s = str(x)
    return s if len(s) <= n else s[:n] + "..."


# ----- main application ---------------------------------------------------- #


class EVotingApp:
    def __init__(self, root):
        self.root = root
        root.title("E-Voting — Paillier homomorphic tally")
        root.geometry("1180x760")
        root.minsize(1000, 640)

        # ----- state ----- #
        self.ca = None
        self.election = None
        self.voters = {}        # voter_id -> Voter
        self.next_voter_idx = 0
        self.attack_log_lines = []
        self.activity_lines = []

        # ----- ttk styling ----- #
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("Header.TLabel", font=HEADER_FONT)
        style.configure("Status.TLabel", padding=8, background=COLOR_HEADER_BG)
        style.configure("OK.TLabel", foreground=COLOR_OK, font=("TkDefaultFont", 10, "bold"))
        style.configure("Bad.TLabel", foreground=COLOR_BAD, font=("TkDefaultFont", 10, "bold"))
        style.configure("Muted.TLabel", foreground=COLOR_MUTED)

        # ----- top status bar ----- #
        self.status_var = tk.StringVar(value="")
        ttk.Label(root, textvariable=self.status_var, style="Status.TLabel",
                  anchor="w").pack(side="top", fill="x")

        # ----- notebook ----- #
        self.nb = ttk.Notebook(root)
        self.nb.pack(fill="both", expand=True, padx=8, pady=8)

        self.tab_setup = ttk.Frame(self.nb, padding=10)
        self.tab_voters = ttk.Frame(self.nb, padding=10)
        self.tab_vote = ttk.Frame(self.nb, padding=10)
        self.tab_verify = ttk.Frame(self.nb, padding=10)
        self.tab_attacks = ttk.Frame(self.nb, padding=10)
        self.tab_tally = ttk.Frame(self.nb, padding=10)
        self.tab_box = ttk.Frame(self.nb, padding=10)

        self.nb.add(self.tab_setup, text="1. Setup")
        self.nb.add(self.tab_voters, text="2. Voters")
        self.nb.add(self.tab_vote, text="3. Vote")
        self.nb.add(self.tab_verify, text="4. Verify")
        # self.nb.add(self.tab_attacks, text="5. Attacks")
        self.nb.add(self.tab_tally, text="5. Tally")
        self.nb.add(self.tab_box, text="6. Ballot Box")

        self._build_setup_tab()
        self._build_voters_tab()
        self._build_vote_tab()
        self._build_verify_tab()
        # self._build_attacks_tab() no needed feature
        self._build_tally_tab()
        self._build_box_tab()

        self.refresh_all()

    # ===================================================================== #
    #  helpers
    # ===================================================================== #

    def busy(self, busy=True):
        self.root.config(cursor="watch" if busy else "")
        self.root.update_idletasks()

    def log_activity(self, msg):
        self.activity_lines.append(msg)
        if len(self.activity_lines) > 200:
            self.activity_lines = self.activity_lines[-200:]
        if hasattr(self, "setup_log"):
            self.setup_log.config(state="normal")
            self.setup_log.delete("1.0", "end")
            self.setup_log.insert("end", "\n".join(self.activity_lines))
            self.setup_log.see("end")
            self.setup_log.config(state="disabled")

    def refresh_status(self):
        if self.election is None:
            self.status_var.set(
                "  No election initialized.  Go to the Setup tab to begin."
            )
            return
        voted = len(self.election.ballots)
        registered = len(self.voters)
        phase = self.election.phase
        self.status_var.set(
            f"  Election: {self.election.election_id}   |   "
            f"Phase: {phase}   |   "
            f"Candidates: {len(self.election.candidates)}   |   "
            f"Registered: {registered}/{self.election.expected_voters}   |   "
            f"Voted: {voted}/{self.election.expected_voters}"
        )

    def refresh_all(self):
        self.refresh_status()
        self._refresh_voters_tab()
        self._refresh_vote_tab()
        self._refresh_verify_tab()
        self._refresh_tally_tab()
        self._refresh_box_tab()

    # ===================================================================== #
    #  TAB 1: SETUP
    # ===================================================================== #

    def _build_setup_tab(self):
        f = self.tab_setup

        ttk.Label(f, text="Election parameters", style="Header.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))

        ttk.Label(f, text="Election name:").grid(row=1, column=0, sticky="e", padx=4, pady=2)
        self.election_name_var = tk.StringVar(value="Election 2026")
        ttk.Entry(f, textvariable=self.election_name_var, width=30).grid(
            row=1, column=1, sticky="w", pady=2)

        ttk.Label(f, text="Expected voters (sets base M = N+1):").grid(
            row=2, column=0, sticky="e", padx=4, pady=2)
        self.expected_voters_var = tk.IntVar(value=10)
        ttk.Spinbox(f, from_=2, to=100, textvariable=self.expected_voters_var,
                    width=8).grid(row=2, column=1, sticky="w", pady=2)

        ttk.Label(f, text="Key size (bits):").grid(row=3, column=0, sticky="e", padx=4, pady=2)
        self.bits_var = tk.IntVar(value=512)
        bits_combo = ttk.Combobox(f, textvariable=self.bits_var, width=8,
                                  values=[256, 512, 1024], state="readonly")
        bits_combo.grid(row=3, column=1, sticky="w", pady=2)

        # candidates list
        ttk.Label(f, text="Candidates / party lists:").grid(
            row=4, column=0, sticky="ne", padx=4, pady=(8, 2))
        cand_frame = ttk.Frame(f)
        cand_frame.grid(row=4, column=1, sticky="w", pady=(8, 2))
        self.cand_listbox = tk.Listbox(cand_frame, width=32, height=6,
                                       activestyle="dotbox", exportselection=False)
        for c in ("Party A", "Party B", "Party C"):
            self.cand_listbox.insert("end", c)
        self.cand_listbox.pack(side="left")
        cand_btns = ttk.Frame(cand_frame)
        cand_btns.pack(side="left", padx=8)
        self.cand_entry_var = tk.StringVar()
        ttk.Entry(cand_btns, textvariable=self.cand_entry_var, width=22).pack(pady=2)
        ttk.Button(cand_btns, text="Add", command=self._cand_add).pack(fill="x", pady=2)
        ttk.Button(cand_btns, text="Remove selected", command=self._cand_remove).pack(fill="x", pady=2)
        ttk.Button(cand_btns, text="Reset to defaults", command=self._cand_reset).pack(fill="x", pady=2)

        # init button
        self.init_btn = ttk.Button(f, text="Initialize election (generate CA + Paillier keys)",
                                   command=self._initialize_election)
        self.init_btn.grid(row=5, column=0, columnspan=2, sticky="w", pady=(14, 6))

        # log area
        ttk.Label(f, text="Activity log:", style="Header.TLabel").grid(
            row=6, column=0, columnspan=2, sticky="w", pady=(12, 2))
        log_frame = ttk.Frame(f)
        log_frame.grid(row=7, column=0, columnspan=2, sticky="nsew")
        f.grid_rowconfigure(7, weight=1)
        f.grid_columnconfigure(1, weight=1)

        self.setup_log = tk.Text(log_frame, height=12, wrap="word", state="disabled",
                                  font=MONOSPACE)
        sb = ttk.Scrollbar(log_frame, orient="vertical", command=self.setup_log.yview)
        self.setup_log.configure(yscrollcommand=sb.set)
        self.setup_log.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

    def _cand_add(self):
        name = self.cand_entry_var.get().strip()
        if not name:
            return
        existing = list(self.cand_listbox.get(0, "end"))
        if name in existing:
            messagebox.showwarning("Duplicate", f"Candidate {name!r} already in the list.")
            return
        self.cand_listbox.insert("end", name)
        self.cand_entry_var.set("")

    def _cand_remove(self):
        sel = self.cand_listbox.curselection()
        if sel:
            self.cand_listbox.delete(sel[0])

    def _cand_reset(self):
        self.cand_listbox.delete(0, "end")
        for c in ("Party A", "Party B", "Party C"):
            self.cand_listbox.insert("end", c)

    def _initialize_election(self):
        if self.election is not None:
            if not messagebox.askyesno(
                "Reinitialize?",
                "An election already exists. Reinitialising will discard all voters and "
                "ballots. Continue?",
            ):
                return

        candidates = list(self.cand_listbox.get(0, "end"))
        if len(candidates) < 2:
            messagebox.showerror("Setup error", "Need at least two candidates.")
            return
        expected = self.expected_voters_var.get()
        if expected < 2:
            messagebox.showerror("Setup error", "Need at least two voters.")
            return
        bits = self.bits_var.get()

        self.busy(True)
        try:
            self.log_activity(f"Initializing election '{self.election_name_var.get()}'...")
            self.log_activity(f"  Generating CA RSA-{bits} keys (this is slow at higher bits)...")
            self.root.update_idletasks()
            self.ca = CA(name="CentralCA", bits=bits)
            self.log_activity(f"  CA n = {short(self.ca.pub['n'])} ({self.ca.pub['n'].bit_length()} bits)")

            self.log_activity(f"  Generating election Paillier-{bits} keypair...")
            self.root.update_idletasks()
            self.election = Election(
                self.ca, candidates=candidates, expected_voters=expected,
                paillier_bits=bits,
            )
            self.log_activity(f"  election_id = {self.election.election_id}")
            self.log_activity(f"  Paillier n = {short(self.election.pub['n'])} "
                              f"({self.election.pub['n'].bit_length()} bits)")
            self.log_activity(f"  base M = {self.election.base_M}  "
                              f"(M^k_max = {self.election.max_plaintext.bit_length()} bits)")

            self.voters = {}
            self.next_voter_idx = 0
            self.refresh_all()
            self.nb.select(self.tab_voters)
        except Exception as e:
            messagebox.showerror("Setup failed", str(e))
        finally:
            self.busy(False)

    # ===================================================================== #
    #  TAB 2: VOTERS
    # ===================================================================== #

    def _build_voters_tab(self):
        f = self.tab_voters

        ttk.Label(f, text="Voter registration", style="Header.TLabel").pack(anchor="w")
        ttk.Label(f, text="The CA issues an RSA keypair + signed certificate to each new voter. "
                          "The certificate is what the election authority trusts during voting.",
                  style="Muted.TLabel").pack(anchor="w", pady=(0, 8))

        btn_row = ttk.Frame(f)
        btn_row.pack(fill="x", pady=4)
        ttk.Button(btn_row, text="Register one voter",
                   command=self._register_one).pack(side="left", padx=(0, 6))
        ttk.Button(btn_row, text="Register ALL remaining voters",
                   command=self._register_all).pack(side="left", padx=(0, 6))
        self.voters_progress = ttk.Progressbar(btn_row, length=200, mode="determinate")
        self.voters_progress.pack(side="left", padx=10)

        body = ttk.Frame(f)
        body.pack(fill="both", expand=True, pady=8)
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=2)
        body.grid_rowconfigure(0, weight=1)

        # voters listbox
        left = ttk.Frame(body)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        ttk.Label(left, text="Registered voters:").pack(anchor="w")
        self.voters_listbox = tk.Listbox(left, exportselection=False, font=MONOSPACE)
        self.voters_listbox.pack(fill="both", expand=True)
        self.voters_listbox.bind("<<ListboxSelect>>", self._on_voter_select)

        # voter details
        right = ttk.Frame(body)
        right.grid(row=0, column=1, sticky="nsew")
        ttk.Label(right, text="Voter details:").pack(anchor="w")
        self.voter_details = tk.Text(right, height=20, wrap="word", state="disabled",
                                      font=MONOSPACE)
        self.voter_details.pack(fill="both", expand=True)

    def _set_text(self, widget, text):
        widget.config(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", text)
        widget.config(state="disabled")

    def _register_one(self):
        if self.election is None:
            messagebox.showinfo("No election", "Initialise an election first.")
            return
        if len(self.voters) >= self.election.expected_voters:
            messagebox.showinfo("Roll full", "Voter roll is already full.")
            return
        self.busy(True)
        try:
            vid = f"voter-{self.next_voter_idx:03d}"
            self.next_voter_idx += 1
            v = Voter(vid, self.ca, bits=self.bits_var.get())
            self.voters[vid] = v
            self.log_activity(f"Registered {vid} (RSA pub n={short(v.pub['n'])})")
            self.refresh_all()
            # auto-select the new voter
            try:
                idx = list(self.voters.keys()).index(vid)
                self.voters_listbox.selection_clear(0, "end")
                self.voters_listbox.selection_set(idx)
                self._on_voter_select()
            except ValueError:
                pass
        except Exception as e:
            messagebox.showerror("Registration failed", str(e))
        finally:
            self.busy(False)

    def _register_all(self):
        if self.election is None:
            messagebox.showinfo("No election", "Initialise an election first.")
            return
        remaining = self.election.expected_voters - len(self.voters)
        if remaining <= 0:
            messagebox.showinfo("Roll full", "Voter roll is already full.")
            return
        self.voters_progress["maximum"] = remaining
        self.voters_progress["value"] = 0
        self.busy(True)
        try:
            for i in range(remaining):
                vid = f"voter-{self.next_voter_idx:03d}"
                self.next_voter_idx += 1
                v = Voter(vid, self.ca, bits=self.bits_var.get())
                self.voters[vid] = v
                self.voters_progress["value"] = i + 1
                self.root.update()
            self.log_activity(f"Registered {remaining} voters in bulk.")
            self.refresh_all()
        except Exception as e:
            messagebox.showerror("Bulk registration failed", str(e))
        finally:
            self.busy(False)
            self.voters_progress["value"] = 0

    def _refresh_voters_tab(self):
        if not hasattr(self, "voters_listbox"):
            return
        sel = self.voters_listbox.curselection()
        prev = self.voters_listbox.get(sel[0]) if sel else None
        self.voters_listbox.delete(0, "end")
        for vid, v in self.voters.items():
            mark = "✓" if (self.election and vid in self.election.ballots) else " "
            self.voters_listbox.insert("end", f"[{mark}] {vid}")
        if prev:
            for i in range(self.voters_listbox.size()):
                if prev in self.voters_listbox.get(i):
                    self.voters_listbox.selection_set(i)
                    break

    def _on_voter_select(self, *_):
        sel = self.voters_listbox.curselection()
        if not sel:
            return
        text = self.voters_listbox.get(sel[0])
        vid = text.split()[-1]
        v = self.voters.get(vid)
        if v is None:
            return
        voted = vid in self.election.ballots if self.election else False
        ballot = self.election.ballots.get(vid) if voted else None
        lines = [
            f"voter_id      : {vid}",
            f"RSA pub n     : {v.pub['n']}",
            f"RSA pub e     : {v.pub['e']}",
            f"CA name       : {v.cert['ca_name']}",
            f"CA signature  : {short(v.cert['ca_sig'], 40)}",
            f"Voted         : {'YES' if voted else 'no'}",
        ]
        if ballot:
            lines += [
                "",
                "--- recorded ballot ---",
                f"election_id   : {ballot['election_id']}",
                f"timestamp     : {ballot['timestamp']:.3f}",
                f"ciphertext    : {short(ballot['ciphertext'], 60)}",
                f"voter_sig     : {short(ballot['voter_sig'], 60)}",
            ]
        if v.receipt:
            r = v.receipt
            lines += [
                "",
                "--- private receipt (this voter's secret) ---",
                f"choice index  : {r['choice']}",
                f"plaintext m   : {r['plaintext']}  (= base_M^choice)",
                f"randomness r  : {short(r['r'], 60)}",
            ]
        self._set_text(self.voter_details, "\n".join(lines))

    # ===================================================================== #
    #  TAB 3: VOTE
    # ===================================================================== #

    def _build_vote_tab(self):
        f = self.tab_vote
        ttk.Label(f, text="Cast a ballot", style="Header.TLabel").pack(anchor="w")
        ttk.Label(f, text="The voter encrypts their candidate index as M^index under "
                          "the election Paillier key. Randomness r is kept as a private receipt.",
                  style="Muted.TLabel").pack(anchor="w", pady=(0, 8))

        top = ttk.Frame(f)
        top.pack(fill="x", pady=4)
        ttk.Label(top, text="Voter:").pack(side="left", padx=(0, 4))
        self.vote_voter_var = tk.StringVar()
        self.vote_voter_combo = ttk.Combobox(top, textvariable=self.vote_voter_var,
                                              width=18, state="readonly")
        self.vote_voter_combo.pack(side="left", padx=(0, 12))

        ttk.Label(top, text="Candidate:").pack(side="left", padx=(0, 4))
        self.vote_choice_var = tk.StringVar()
        self.vote_choice_combo = ttk.Combobox(top, textvariable=self.vote_choice_var,
                                                width=22, state="readonly")
        self.vote_choice_combo.pack(side="left", padx=(0, 12))

        ttk.Button(top, text="Cast vote",
                   command=self._cast_selected).pack(side="left", padx=4)
        ttk.Button(top, text="Random vote for selected",
                   command=self._cast_random_one).pack(side="left", padx=4)
        ttk.Button(top, text="Random votes for ALL remaining voters",
                   command=self._cast_random_all).pack(side="left", padx=4)

        ttk.Label(f, text="Last ballot:", style="Header.TLabel").pack(anchor="w", pady=(12, 2))
        self.vote_output = tk.Text(f, height=18, wrap="word", state="disabled",
                                    font=MONOSPACE)
        self.vote_output.pack(fill="both", expand=True)

    def _refresh_vote_tab(self):
        if not hasattr(self, "vote_voter_combo"):
            return
        if self.election is None:
            self.vote_voter_combo["values"] = []
            self.vote_choice_combo["values"] = []
            return
        unvoted = [vid for vid in self.voters if vid not in self.election.ballots]
        self.vote_voter_combo["values"] = unvoted
        if self.vote_voter_var.get() not in unvoted:
            self.vote_voter_var.set(unvoted[0] if unvoted else "")
        self.vote_choice_combo["values"] = self.election.candidates
        if self.vote_choice_var.get() not in self.election.candidates:
            self.vote_choice_var.set(self.election.candidates[0]
                                      if self.election.candidates else "")

    def _do_cast(self, vid, choice_index):
        v = self.voters[vid]
        ballot = v.cast(
            self.election.pub, self.election.election_id, choice_index,
            num_candidates=len(self.election.candidates),
            base_M=self.election.base_M,
        )
        ok, reason = self.election.submit(ballot)
        return ballot, ok, reason

    def _display_ballot(self, vid, ballot, ok, reason, choice_index):
        v = self.voters[vid]
        cand_name = self.election.candidates[choice_index]
        lines = [
            f"Voter         : {vid}",
            f"Choice        : {cand_name} (index {choice_index})",
            f"Encoded plain : M^{choice_index} = {self.election.base_M ** choice_index}",
            f"Receipt r     : {short(v.receipt['r'], 60)}  (kept private)",
            "",
            f"Ciphertext    : {short(ballot['ciphertext'], 60)}",
            f"Voter sig     : {short(ballot['voter_sig'], 60)}",
            f"election_id   : {ballot['election_id']}",
            f"timestamp     : {ballot['timestamp']:.3f}",
            "",
            f"Submission    : {'ACCEPTED' if ok else 'REJECTED'} — {reason}",
        ]
        self._set_text(self.vote_output, "\n".join(lines))

    def _cast_selected(self):
        if self.election is None:
            return
        vid = self.vote_voter_var.get()
        cand = self.vote_choice_var.get()
        if not vid or not cand:
            return
        idx = self.election.candidates.index(cand)
        self.busy(True)
        try:
            ballot, ok, reason = self._do_cast(vid, idx)
            self._display_ballot(vid, ballot, ok, reason, idx)
            self.log_activity(f"{vid} voted for {cand} -> {reason}")
            self.refresh_all()
        finally:
            self.busy(False)

    def _cast_random_one(self):
        if self.election is None:
            return
        vid = self.vote_voter_var.get()
        if not vid:
            return
        idx = secrets.randbelow(len(self.election.candidates))
        self.vote_choice_var.set(self.election.candidates[idx])
        self._cast_selected()

    def _cast_random_all(self):
        if self.election is None:
            return
        unvoted = [vid for vid in self.voters if vid not in self.election.ballots]
        if not unvoted:
            messagebox.showinfo("Nothing to do", "All registered voters have already voted.")
            return
        self.busy(True)
        try:
            for vid in unvoted:
                idx = secrets.randbelow(len(self.election.candidates))
                ballot, ok, reason = self._do_cast(vid, idx)
                self.log_activity(f"{vid} random-voted for "
                                  f"{self.election.candidates[idx]} -> {reason}")
                self._display_ballot(vid, ballot, ok, reason, idx)
                self.root.update()
            self.refresh_all()
        finally:
            self.busy(False)

    # ===================================================================== #
    #  TAB 4: VERIFY
    # ===================================================================== #

    def _build_verify_tab(self):
        f = self.tab_verify
        ttk.Label(f, text="Receipt-based ballot verification",
                  style="Header.TLabel").pack(anchor="w")
        ttk.Label(f,
                  text="Each voter saved the random r used during encryption. They can "
                       "re-encrypt their (known) plaintext with that same r and compare it "
                       "with what the ballot box claims is theirs. A match proves no tampering.",
                  style="Muted.TLabel", wraplength=900).pack(anchor="w", pady=(0, 8))

        row = ttk.Frame(f)
        row.pack(fill="x", pady=6)
        ttk.Label(row, text="Voter:").pack(side="left", padx=(0, 4))
        self.verify_voter_var = tk.StringVar()
        self.verify_voter_combo = ttk.Combobox(row, textvariable=self.verify_voter_var,
                                                width=18, state="readonly")
        self.verify_voter_combo.pack(side="left", padx=(0, 12))
        ttk.Button(row, text="Verify my ballot",
                   command=self._verify_one).pack(side="left", padx=4)
        ttk.Button(row, text="Verify ALL voters",
                   command=self._verify_all).pack(side="left", padx=4)

        self.verify_result_var = tk.StringVar(value="")
        self.verify_result_label = ttk.Label(f, textvariable=self.verify_result_var)
        self.verify_result_label.pack(anchor="w", pady=(8, 4))

        self.verify_output = tk.Text(f, height=20, wrap="word", state="disabled",
                                      font=MONOSPACE)
        self.verify_output.pack(fill="both", expand=True)

    def _refresh_verify_tab(self):
        if not hasattr(self, "verify_voter_combo"):
            return
        if self.election is None:
            self.verify_voter_combo["values"] = []
            return
        voted = list(self.election.ballots.keys())
        self.verify_voter_combo["values"] = voted
        if self.verify_voter_var.get() not in voted:
            self.verify_voter_var.set(voted[0] if voted else "")

    def _verify_one(self):
        if self.election is None:
            return
        vid = self.verify_voter_var.get()
        if not vid:
            return
        v = self.voters[vid]
        stored = self.election.stored_ciphertext(vid)
        ok = v.verify_recorded(self.election.pub, stored)

        r = v.receipt
        recomputed = stored  # if ok, they're equal
        # Always recompute regardless so we can display side by side.
        import paillier
        recomputed, _ = paillier.encrypt(self.election.pub, r["plaintext"], r=r["r"])

        lines = [
            f"Voter         : {vid}",
            f"Choice        : index {r['choice']} ({self.election.candidates[r['choice']]})",
            f"Plaintext m   : {r['plaintext']}",
            f"Randomness r  : {short(r['r'], 60)}",
            "",
            f"Stored c      : {short(stored, 60)}",
            f"Recomputed c' : {short(recomputed, 60)}",
            f"c == c'       : {'YES — ballot box is faithful' if ok else 'NO — TAMPERING DETECTED'}",
        ]
        self._set_text(self.verify_output, "\n".join(lines))
        self.verify_result_var.set("Result: MATCH ✓" if ok else "Result: MISMATCH ✗")
        self.verify_result_label.configure(style="OK.TLabel" if ok else "Bad.TLabel")

    def _verify_all(self):
        if self.election is None:
            return
        ok_count = 0
        bad = []
        for vid in self.election.ballots:
            v = self.voters[vid]
            stored = self.election.stored_ciphertext(vid)
            if v.verify_recorded(self.election.pub, stored):
                ok_count += 1
            else:
                bad.append(vid)
        total = len(self.election.ballots)
        lines = [f"Verified {ok_count}/{total} ballots"]
        if bad:
            lines.append(f"FAILED for: {', '.join(bad)}")
        else:
            lines.append("All recorded ballots match the receipts. Ballot box is faithful.")
        self._set_text(self.verify_output, "\n".join(lines))
        self.verify_result_var.set("All ✓" if not bad else "Some FAILED ✗")
        self.verify_result_label.configure(style="OK.TLabel" if not bad else "Bad.TLabel")

    # ===================================================================== #
    #  TAB 5: ATTACKS
    # ===================================================================== #

    # def _build_attacks_tab(self):
    #     f = self.tab_attacks
    #     ttk.Label(f, text="Attack simulator", style="Header.TLabel").pack(anchor="w")
    #     ttk.Label(f,
    #               text="Each button below mounts a known attack and reports whether the system "
    #                    "rejected it (good) or accepted it (bad).",
    #               style="Muted.TLabel", wraplength=900).pack(anchor="w", pady=(0, 8))

    #     btns = ttk.Frame(f)
    #     btns.pack(fill="x", pady=4)
    #     ttk.Button(btns, text="Double vote",
    #                command=self._atk_double_vote).pack(side="left", padx=3, pady=2)
    #     ttk.Button(btns, text="Forged certificate (rogue CA)",
    #                command=self._atk_rogue_ca).pack(side="left", padx=3, pady=2)
    #     ttk.Button(btns, text="ID spoofing (same id, new keys)",
    #                command=self._atk_id_spoof).pack(side="left", padx=3, pady=2)
    #     ttk.Button(btns, text="Tamper with ciphertext in transit",
    #                command=self._atk_tamper_transit).pack(side="left", padx=3, pady=2)
    #     ttk.Button(btns, text="Wrong-election ballot",
    #                command=self._atk_wrong_election).pack(side="left", padx=3, pady=2)
    #     ttk.Button(btns, text="Clear log",
    #                command=self._atk_clear).pack(side="right", padx=3, pady=2)

    #     self.attack_output = tk.Text(f, wrap="word", state="disabled", font=MONOSPACE)
    #     self.attack_output.pack(fill="both", expand=True, pady=(8, 0))

    # def _atk_print(self, msg):
    #     self.attack_log_lines.append(msg)
    #     self._set_text(self.attack_output, "\n".join(self.attack_log_lines))
    #     self.attack_output.see("end")

    # def _atk_clear(self):
    #     self.attack_log_lines = []
    #     self._set_text(self.attack_output, "")

    # def _need_election_and_a_vote(self):
    #     if self.election is None:
    #         messagebox.showinfo("No election", "Initialise an election first.")
    #         return False
    #     if not self.election.ballots:
    #         messagebox.showinfo("No ballots yet", "Cast at least one ballot first.")
    #         return False
    #     return True

    # def _atk_double_vote(self):
    #     if not self._need_election_and_a_vote():
    #         return
    #     vid = next(iter(self.election.ballots))
    #     v = self.voters[vid]
    #     idx = (v.receipt["choice"] + 1) % len(self.election.candidates)
    #     ballot = v.cast(
    #         self.election.pub, self.election.election_id, idx,
    #         num_candidates=len(self.election.candidates),
    #         base_M=self.election.base_M,
    #     )
    #     ok, reason = self.election.submit(ballot)
    #     self._atk_print(
    #         f"[double-vote ] {vid} replayed with new choice -> "
    #         f"accepted={ok}, reason={reason!r}  "
    #         f"=> {'BAD' if ok else 'GOOD (rejected)'}"
    #     )

    # def _atk_rogue_ca(self):
    #     if self.election is None:
    #         messagebox.showinfo("No election", "Initialise an election first.")
    #         return
    #     self.busy(True)
    #     try:
    #         rogue_ca = CA(name="RogueCA", bits=self.bits_var.get())
    #         rogue = Voter("voter-rogue", rogue_ca, bits=self.bits_var.get())
    #         forged = rogue.cast(
    #             self.election.pub, self.election.election_id, 0,
    #             num_candidates=len(self.election.candidates),
    #             base_M=self.election.base_M,
    #         )
    #         ok, reason = self.election.submit(forged)
    #         self._atk_print(
    #             f"[rogue-CA    ] outsider with cert signed by 'RogueCA' -> "
    #             f"accepted={ok}, reason={reason!r}  "
    #             f"=> {'BAD' if ok else 'GOOD (rejected)'}"
    #         )
    #     finally:
    #         self.busy(False)

    # def _atk_id_spoof(self):
    #     """Attacker generates their own RSA keys and a CA-signed cert under
    #     an existing voter's id. Our CA refuses to re-issue, so the attack
    #     can't even get a valid cert."""
    #     if not self._need_election_and_a_vote():
    #         return
    #     vid = next(iter(self.voters))
    #     try:
    #         spoof = Voter(vid, self.ca, bits=self.bits_var.get())
    #         forged = spoof.cast(
    #             self.election.pub, self.election.election_id, 0,
    #             num_candidates=len(self.election.candidates),
    #             base_M=self.election.base_M,
    #         )
    #         ok, reason = self.election.submit(forged)
    #         self._atk_print(
    #             f"[id-spoof    ] tried to re-register {vid} -> "
    #             f"accepted={ok}, reason={reason!r}  "
    #             f"=> {'BAD' if ok else 'GOOD (rejected)'}"
    #         )
    #     except ValueError as e:
    #         self._atk_print(
    #             f"[id-spoof    ] CA refused to re-issue cert for {vid}: {e}  "
    #             f"=> GOOD (rejected at CA)"
    #         )

    # def _atk_tamper_transit(self):
    #     """An attacker on the network flips one bit of the ciphertext. The
    #     voter signature is over the ciphertext, so the signature should fail."""
    #     if not self._need_election_and_a_vote():
    #         return
    #     # Pick any unvoted voter, build a legit ballot, mutate it, submit.
    #     unvoted = [vid for vid in self.voters if vid not in self.election.ballots]
    #     if not unvoted:
    #         self._atk_print("[tamper      ] no unvoted voter available to try this attack")
    #         return
    #     vid = unvoted[0]
    #     v = self.voters[vid]
    #     # Build a fresh ballot but DON'T let it become the official cast — we'll
    #     # mutate it before submission. Pass through a private helper to avoid
    #     # poisoning the voter's receipt.
    #     import paillier, rsa_sig
    #     from voter import ballot_payload
    #     choice = 0
    #     m = pow(self.election.base_M, choice)
    #     c, r = paillier.encrypt(self.election.pub, m)
    #     ballot = {
    #         "cert": v.cert,
    #         "ciphertext": c,
    #         "election_id": self.election.election_id,
    #         "timestamp": 0.0,
    #         "voter_sig": 0,
    #     }
    #     ballot["voter_sig"] = rsa_sig.sign(v.priv, ballot_payload(ballot))
    #     # Attacker flips a bit of the ciphertext after the voter signed.
    #     ballot["ciphertext"] ^= 1
    #     ok, reason = self.election.submit(ballot)
    #     self._atk_print(
    #         f"[tamper      ] flipped 1 bit of ciphertext in transit -> "
    #         f"accepted={ok}, reason={reason!r}  "
    #         f"=> {'BAD' if ok else 'GOOD (rejected)'}"
    #     )

    # def _atk_wrong_election(self):
    #     if self.election is None:
    #         messagebox.showinfo("No election", "Initialise an election first.")
    #         return
    #     unvoted = [vid for vid in self.voters if vid not in self.election.ballots]
    #     if not unvoted:
    #         self._atk_print("[xelection   ] no unvoted voter available")
    #         return
    #     vid = unvoted[0]
    #     v = self.voters[vid]
    #     # Voter accidentally (or maliciously) signs for the wrong election id.
    #     ballot = v.cast(
    #         self.election.pub, "election-other", 0,
    #         num_candidates=len(self.election.candidates),
    #         base_M=self.election.base_M,
    #     )
    #     ok, reason = self.election.submit(ballot)
    #     # Undo the receipt-mutation that cast() may have caused.
    #     if v.receipt and v.receipt.get("ciphertext") == ballot["ciphertext"]:
    #         v.receipt = None
    #     self._atk_print(
    #         f"[xelection   ] ballot tagged with wrong election_id -> "
    #         f"accepted={ok}, reason={reason!r}  "
    #         f"=> {'BAD' if ok else 'GOOD (rejected)'}"
    #     )

    # ===================================================================== #
    #  TAB 6: TALLY
    # ===================================================================== #

    def _build_tally_tab(self):
        f = self.tab_tally
        ttk.Label(f, text="Homomorphic tally", style="Header.TLabel").pack(anchor="w")
        ttk.Label(f,
                  text="Closing the election multiplies every ciphertext together "
                       "(=> additive plaintext) and runs ONE decryption. Individual "
                       "ballots are never decrypted.",
                  style="Muted.TLabel", wraplength=900).pack(anchor="w", pady=(0, 8))

        row = ttk.Frame(f)
        row.pack(fill="x", pady=4)
        self.tally_btn = ttk.Button(row, text="Close voting and tally",
                                     command=self._do_tally)
        self.tally_btn.pack(side="left", padx=(0, 6))
        ttk.Button(row, text="Reset election state",
                   command=self._reset).pack(side="right")

        body = ttk.Frame(f)
        body.pack(fill="both", expand=True, pady=8)
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        left = ttk.Frame(body)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        ttk.Label(left, text="Aggregate details:").pack(anchor="w")
        self.tally_output = tk.Text(left, height=16, wrap="word", state="disabled",
                                     font=MONOSPACE)
        self.tally_output.pack(fill="both", expand=True)

        right = ttk.Frame(body)
        right.grid(row=0, column=1, sticky="nsew")
        ttk.Label(right, text="Results:").pack(anchor="w")
        self.tally_canvas = tk.Canvas(right, bg="white", highlightthickness=1,
                                       highlightbackground="#ccc")
        self.tally_canvas.pack(fill="both", expand=True)
        self.tally_canvas.bind("<Configure>", lambda e: self._draw_chart())

    def _refresh_tally_tab(self):
        if not hasattr(self, "tally_btn"):
            return
        # Re-draw whatever's cached
        self._draw_chart()

    def _do_tally(self):
        if self.election is None:
            messagebox.showinfo("No election", "Initialise an election first.")
            return
        if not self.election.ballots:
            messagebox.showinfo("Empty", "No ballots to tally.")
            return
        if self.election.phase == PHASE_VOTING:
            self.election.close()
        counts, encrypted, plain_sum = self.election.tally()
        self._last_counts = counts

        M = self.election.base_M
        cand_count = len(self.election.candidates)
        # Show base-M digit expansion to make the decoding step concrete
        digits = []
        x = plain_sum
        for i, c in enumerate(self.election.candidates):
            digits.append((c, x % M))
            x //= M
        digit_lines = [f"    digit_{i} ({name}) = {d}" for i, (name, d) in enumerate(digits)]

        lines = [
            f"Total ballots tallied : {sum(counts.values())}",
            f"Base M                : {M}",
            f"Candidates            : {cand_count}",
            "",
            f"Encrypted aggregate   : {short(encrypted, 60)}",
            "  (this is the only ciphertext ever decrypted)",
            "",
            f"Decryption -> integer : {plain_sum}",
            f"Base-{M} expansion:",
            *digit_lines,
            "",
            "Decoded per-candidate counts:",
        ] + [f"    {name:>20} : {n}" for name, n in counts.items()]
        self._set_text(self.tally_output, "\n".join(lines))
        self._draw_chart()
        self.refresh_status()
        self.log_activity(f"Tally completed. Counts: {counts}")

    def _draw_chart(self):
        if not hasattr(self, "tally_canvas"):
            return
        counts = getattr(self, "_last_counts", None)
        c = self.tally_canvas
        c.delete("all")
        if not counts:
            c.create_text(c.winfo_width() / 2, c.winfo_height() / 2,
                          text="(no tally yet)", fill=COLOR_MUTED)
            return
        w = c.winfo_width()
        h = c.winfo_height()
        if w < 20 or h < 20:
            return
        ml, mr, mt, mb = 150, 60, 18, 18
        bar_area_w = max(40, w - ml - mr)
        bar_area_h = max(40, h - mt - mb)
        n = len(counts)
        bar_h = bar_area_h / n * 0.7
        gap = bar_area_h / n * 0.3
        max_count = max(counts.values()) or 1

        for i, (name, count) in enumerate(counts.items()):
            y0 = mt + i * (bar_h + gap)
            y1 = y0 + bar_h
            c.create_text(ml - 8, (y0 + y1) / 2, text=name, anchor="e",
                          font=("TkDefaultFont", 10, "bold"))
            bar_w = (count / max_count) * bar_area_w
            c.create_rectangle(ml, y0, ml + bar_w, y1, fill=COLOR_BAR, width=0)
            label_x = ml + bar_w + 4
            c.create_text(label_x, (y0 + y1) / 2, text=str(count), anchor="w",
                          font=("TkDefaultFont", 10, "bold"))

    def _reset(self):
        if self.election is None:
            return
        if not messagebox.askyesno(
            "Reset?",
            "Wipe all voters and ballots, keep the CA and parameters? "
            "(Use 'Initialize election' on the Setup tab for a full reset.)",
        ):
            return
        self.election = Election(
            self.ca, candidates=self.election.candidates,
            expected_voters=self.election.expected_voters,
            paillier_bits=self.bits_var.get(),
        )
        self.voters = {}
        self.next_voter_idx = 0
        self._last_counts = None
        self.log_activity("Election state reset (new election_id, new Paillier keys).")
        self.refresh_all()
        self._set_text(self.tally_output, "")

    # ===================================================================== #
    #  TAB 7: BALLOT BOX
    # ===================================================================== #

    def _build_box_tab(self):
        f = self.tab_box
        ttk.Label(f, text="Ballot box (hash-chained log)", style="Header.TLabel").pack(anchor="w")
        ttk.Label(f, text="Every accepted ballot is appended to a chain where each entry hashes "
                          "(prev_hash || entry_data). Modifying any past entry breaks every "
                          "subsequent hash. This is the 'blockchain-like' audit log.",
                  style="Muted.TLabel", wraplength=900).pack(anchor="w", pady=(0, 8))

        row = ttk.Frame(f)
        row.pack(fill="x", pady=4)
        ttk.Button(row, text="Verify chain integrity",
                   command=self._box_verify).pack(side="left", padx=3)
        ttk.Button(row, text="Tamper with selected ballot (demo)",
                   command=self._box_tamper).pack(side="left", padx=3)
        ttk.Button(row, text="Untamper (restore)",
                   command=self._box_untamper).pack(side="left", padx=3)
        self.box_status_var = tk.StringVar(value="")
        self.box_status_label = ttk.Label(row, textvariable=self.box_status_var)
        self.box_status_label.pack(side="right", padx=8)

        cols = ("idx", "voter", "ciphertext", "prev", "hash")
        self.box_tree = ttk.Treeview(f, columns=cols, show="headings", height=18)
        for c, w in zip(cols, (50, 110, 280, 220, 220)):
            self.box_tree.column(c, width=w, anchor="w")
        self.box_tree.heading("idx", text="#")
        self.box_tree.heading("voter", text="voter_id")
        self.box_tree.heading("ciphertext", text="ciphertext")
        self.box_tree.heading("prev", text="prev_hash")
        self.box_tree.heading("hash", text="hash")
        self.box_tree.pack(fill="both", expand=True, pady=8)
        sb = ttk.Scrollbar(f, orient="vertical", command=self.box_tree.yview)
        self.box_tree.configure(yscrollcommand=sb.set)

        self._tamper_backup = None

    def _refresh_box_tab(self):
        if not hasattr(self, "box_tree"):
            return
        self.box_tree.delete(*self.box_tree.get_children())
        if self.election is None:
            return
        for e in self.election.box.chain:
            self.box_tree.insert("", "end", values=(
                e["index"],
                e["voter_id"],
                short(e["ciphertext"], 40),
                e["prev_hash"].hex()[:24] + "...",
                e["hash"].hex()[:24] + "...",
            ))

    def _box_verify(self):
        if self.election is None:
            return
        ok, bad = self.election.box.verify_integrity()
        if ok:
            self.box_status_var.set("Chain integrity: OK ✓")
            self.box_status_label.configure(style="OK.TLabel")
        else:
            self.box_status_var.set(f"Chain integrity: BROKEN at index {bad} ✗")
            self.box_status_label.configure(style="Bad.TLabel")

    def _box_tamper(self):
        if self.election is None or not self.election.box.chain:
            return
        sel = self.box_tree.selection()
        if not sel:
            messagebox.showinfo("Select a ballot",
                                "Click a row in the chain first.")
            return
        idx = int(self.box_tree.item(sel[0])["values"][0])
        entry = self.election.box.chain[idx]
        self._tamper_backup = (idx, entry["ciphertext"])
        entry["ciphertext"] ^= 1  # flip one bit
        self._refresh_box_tab()
        self._box_verify()
        self._atk_print(
            f"[box-tamper  ] flipped a bit in entry #{idx} ciphertext. "
            f"Run 'Verify' to see the chain detect it."
        )

    def _box_untamper(self):
        if self._tamper_backup is None or self.election is None:
            return
        idx, original = self._tamper_backup
        if 0 <= idx < len(self.election.box.chain):
            self.election.box.chain[idx]["ciphertext"] = original
        self._tamper_backup = None
        self._refresh_box_tab()
        self._box_verify()


# ----- entry point --------------------------------------------------------- #


def main():
    root = tk.Tk()
    EVotingApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
