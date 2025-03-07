#  Represent a Dolev-Yao term with methods for parsing and manipulation.
class Term:
    def __init__(self, term_str):
        # print(f"Creating Term: {term_str}")
        self.raw = term_str
        self.type, self.components = self._parse()
        # print(f"Parsed Term: type={self.type}, components={self.components}")
    
    def _parse(self):
        # print("(Parse a term into its components.)")
        term = self.raw.strip()
        # handle encryption: enc(message, key)
        if term.startswith("enc("):
            return self._parse_function("enc", term[4:-1])
        # handle pairing: pair(left, right)
        elif term.startswith("pair("):
            return self._parse_function("pair", term[5:-1])
        # atomic term (agent, nonce, key)
        else:
            return ("atomic", [term])
    
    # Parse a function term by finding the comma that separates arguments.
    def _parse_function(self, func_type, content):
        bracket_count = 0
        comma_pos = -1
        
        for i, char in enumerate(content):
            if char == '(':
                bracket_count += 1
            elif char == ')':
                bracket_count -= 1
            elif char == ',' and bracket_count == 0:
                comma_pos = i
                break
        
        if comma_pos != -1:
            arg1 = content[:comma_pos].strip()
            arg2 = content[comma_pos+1:].strip()
            return (func_type, [arg1, arg2])
        # if we can't parse properly, return as atomic
        return ("atomic", [content])
    
    def __str__(self):
        return self.raw
    def __repr__(self):
        return f"Term({self.raw})"
    def __eq__(self, other):
        if isinstance(other, Term):
            return self.raw == other.raw
        return self.raw == other
    def __hash__(self):
        return hash(self.raw)
# Implement the Dolev-Yao model for protocol analysis.
class DolevYao:
    def __init__(self):
        self.knowledge = set()
    # Add a term to the initial knowledge set.
    def addKnowledge(self, term, agent=""):
        print(f"Adding knowledge to {agent}'s knowledge base: {term}")
        if isinstance(term, str):
            self.knowledge.add(term)
        else:
            self.knowledge.add(str(term))
    # Compute all terms that can be derived from the current knowledge.
    def deriveKnowledge(self, agent=""):
        print(f"\n{agent} starts knowledge derivation...")
        # initialize
        print("Initializing knowledge derivation...")
        Y = self.knowledge.copy()
        print("Computing subterms...")
        st = self._compute_subterms(Y)
        N = len(st)
        i = 0
        # main derivation loop
        while i <= N:
            print(f"\nIteration {i}: Current knowledge: {Y}")
            # apply pairing rule
            Z = Y.copy()
            for t0 in Y:
                for t1 in Y:
                    pair_term = f"pair({t0},{t1})"
                    if pair_term in st and pair_term not in Y:
                        print("Adding pair term:", pair_term)
                        Z.add(pair_term)
            # apply encryption rule
            for t in Y:
                for k in Y:
                    enc_term = f"enc({t},{k})"
                    if enc_term in st and pair_term not in Y:
                        print("Adding encryption term:", enc_term)
                        Z.add(enc_term)
            # apply splitting rule
            for term in Y:
                t = Term(term)
                if t.type == "pair":
                    left, right = t.components
                    if left not in Y or right not in Y:
                        print("Adding split terms:", left, right)
                        Z.add(left)
                        Z.add(right)
            # apply decryption rule
            for term in Y:
                t = Term(term)
                if t.type == "enc":
                    msg, key = t.components
                    if key in Y:
                        if msg not in Y:
                            print("Adding decrypted message:", msg)
                            Z.add(msg)
            # update Y and continue
            Y = Z
            i += 1
        print(f"\nFinal derived knowledge: {Y}")
        return Y
    
    # compute all subterms of the given terms.
    def _compute_subterms(self, terms):
        subterms = set()
        for term_str in terms:
            term = Term(term_str)
            subterms.add(term_str)
            # recursively add components
            if term.type in ["pair", "enc"]:
                for component in term.components:
                    subterms.update(self._compute_subterms([component]))
        return subterms
    
    # check if the target term can be derived from current knowledge.
    def can_derive(self, target):
        derived = self.deriveKnowledge()
        return target in derived

# Implement the Needham-Schroeder Symmetric Key protocol and verify its security.
class NeedhamSchroeder:
    def __init__(self):
        print("Initializing the Needham-Schroeder Symmetric Key protocol...")
        # define agents
        self.alice = "A"
        self.bob = "B"
        self.server = "S"
        self.attacker = "I"
        # define keys
        self.key_as = f"K_AS"  # Key shared between Alice and Server
        self.key_bs = f"K_BS"  # Key shared between Bob and Server
        # knowledge bases
        self.alice_dys = DolevYao()
        self.bob_dys = DolevYao()
        self.server_dys = DolevYao()
        self.attacker_dys = DolevYao()
        # initialize knowledge
        self._init_knowledge()
    # initialize the knowledge of all agents.
    def _init_knowledge(self):
        print("\nInitializing knowledge for all agents...")
        # Alice's knowledge
        for term in [self.alice, self.bob, self.server, self.key_as]:
            self.alice_dys.addKnowledge(term, "Alice")
        # Bob's knowledge
        for term in [self.alice, self.bob, self.server, self.key_bs]:
            self.bob_dys.addKnowledge(term, "Bob")
        # Server's knowledge
        for term in [self.alice, self.bob, self.server, self.key_as, self.key_bs]:
            self.server_dys.addKnowledge(term, "Server")
        # Attacker's knowledge
        for term in [self.alice, self.bob, self.server, self.attacker]:
            self.attacker_dys.addKnowledge(term, "Attacker")
        print("\nKnowledge bases:")
        print("Alice's knowledge:", self.alice_dys.knowledge)
        print("Bob's knowledge:", self.bob_dys.knowledge)
        print("Server's knowledge:", self.server_dys.knowledge)
        print("Attacker's knowledge:", self.attacker_dys.knowledge)

    # simulate the normal Needham-Schroeder protocol.
    def simulateProtocol(self):
        print("\nSimulating normal Needham-Schroeder Symmetric Key protocol...")
        # Step 1: Alice sends her identity, Bob's identity, and a nonce to Server
        na = "Na"
        self.alice_dys.addKnowledge(na, "Alice")
        msg1 = f"pair({self.alice},pair({self.bob},{na}))"
        self.alice_dys.addKnowledge(msg1, "Alice")
        self.server_dys.addKnowledge(msg1, "Server")
        print(f"\nAlice sends to Server: {msg1}")
        print(f"MESSAGE: Alice -> Server: A, B, Na")
        # Step 2: Server generates session key and responds to Alice
        session_key = "K_AB"
        self.server_dys.addKnowledge(session_key, "Server")
        # server creates message for Alice with the session key
        ticket_for_bob = f"enc(pair({session_key},{self.alice}),{self.key_bs})"
        msg2 = f"enc(pair({na},pair({session_key},pair({self.bob},{ticket_for_bob}))),{self.key_as})"
        self.server_dys.addKnowledge(msg2, "Server")
        self.alice_dys.addKnowledge(msg2, "Alice")
        print(f"\nServer sends to Alice: {msg2}")
        print(f"MESSAGE: Server -> Alice: {{Na, K_AB, B, {{K_AB, A}}K_BS}}K_AS")
        # Alice derives session key and ticket for Bob
        alice_derived = self.alice_dys.deriveKnowledge("Alice")
        self.alice_dys.addKnowledge(session_key, "Alice")
        self.alice_dys.addKnowledge(ticket_for_bob, "Alice")
        # Step 3: Alice forwards the ticket to Bob and sends a challenge
        msg3 = ticket_for_bob
        self.alice_dys.addKnowledge(msg3, "Alice")
        self.bob_dys.addKnowledge(msg3, "Bob")
        print(f"\nAlice sends to Bob: {msg3}")
        print(f"MESSAGE: Alice -> Bob: {{K_AB, A}}K_BS")
        # Bob can derive the session key
        bob_derived = self.bob_dys.deriveKnowledge("Bob")
        self.bob_dys.addKnowledge(session_key, "Bob")
        # Step 4: Bob generates a nonce and sends it to Alice, encrypted with session key
        nb = "Nb"
        self.bob_dys.addKnowledge(nb, "Bob")
        msg4 = f"enc({nb},{session_key})"
        self.bob_dys.addKnowledge(msg4, "Bob")
        self.alice_dys.addKnowledge(msg4, "Alice")
        print(f"\nBob sends to Alice: {msg4}")
        print(f"MESSAGE: Bob -> Alice: {{Nb}}K_AB")
        # Alice can derive Bob's nonce
        alice_derived = self.alice_dys.deriveKnowledge("Alice")
        # Step 5: Alice confirms by sending Nb-1 back to Bob
        nb_minus_1 = "Nb-1"
        self.alice_dys.addKnowledge(nb_minus_1, "Alice")
        msg5 = f"enc({nb_minus_1},{session_key})"
        self.alice_dys.addKnowledge(msg5, "Alice")
        self.bob_dys.addKnowledge(msg5, "Bob")
        print(f"\nAlice sends to Bob: {msg5}")
        print(f"MESSAGE: Alice -> Bob: {{Nb-1}}K_AB")
        # Bob verifies the modification of his nonce
        bob_derived = self.bob_dys.deriveKnowledge("Bob")
        return {
            "alice_knowledge": self.alice_dys.knowledge,
            "bob_knowledge": self.bob_dys.knowledge,
            "server_knowledge": self.server_dys.knowledge,
            "shared_session_key": session_key,
            "shared_nonces": [na, nb]
        }
    
    # Simulate the replay attack on the protocol
    def simulateDenningSaccoAttack(self):
        print("\nSimulating replay attack (Denning-Sacco attack)...")
        # run a normal protocol execution first to establish the context
        # Alice's nonce
        na = "Na"
        self.alice_dys.addKnowledge(na, "Alice")
        # attacker intercepts message 1 (Alice to Server)
        msg1 = f"pair({self.alice},pair({self.bob},{na}))"
        self.alice_dys.addKnowledge(msg1, "Alice")
        # attacker intercepts
        self.attacker_dys.addKnowledge(msg1, "Attacker")
        print(f"\nAttacker intercepts: {msg1}")
        print(f"MESSAGE: Alice -> Server (intercepted by Attacker): A, B, Na")
        # attacker learns Na
        self.attacker_dys.deriveKnowledge("Attacker")
        # server responds with session key (attacker can't decrypt this)
        session_key = "K_AB"
        self.server_dys.addKnowledge(session_key, "Server")
        ticket_for_bob = f"enc(pair({session_key},{self.alice}),{self.key_bs})"
        msg2 = f"enc(pair({na},pair({session_key},pair({self.bob},{ticket_for_bob}))),{self.key_as})"
        self.server_dys.addKnowledge(msg2, "Server")
        self.alice_dys.addKnowledge(msg2, "Alice")
        print(f"\nServer sends to Alice: {msg2}")
        print(f"MESSAGE: Server -> Alice: {{Na, K_AB, B, {{K_AB, A}}K_BS}}K_AS")
        # Alice derives session key and forwards ticket to Bob
        self.alice_dys.deriveKnowledge("Alice")
        self.alice_dys.addKnowledge(session_key, "Alice")
        msg3 = ticket_for_bob
        self.alice_dys.addKnowledge(msg3, "Alice")
        # attacker intercepts the ticket to Bob
        self.attacker_dys.addKnowledge(msg3, "Attacker")
        print(f"\nAttacker intercepts ticket: {msg3}")
        print(f"MESSAGE: Alice -> Bob (intercepted by Attacker): {{K_AB, A}}K_BS")
        # Bob receives the ticket and derives the session key
        self.bob_dys.addKnowledge(msg3, "Bob")
        self.bob_dys.deriveKnowledge("Bob")
        self.bob_dys.addKnowledge(session_key, "Bob")
        # Bob generates Nb and sends to Alice
        nb = "Nb"
        self.bob_dys.addKnowledge(nb, "Bob")
        msg4 = f"enc({nb},{session_key})"
        self.bob_dys.addKnowledge(msg4, "Bob")
        # attacker intercepts this message but can't decrypt it yet
        self.attacker_dys.addKnowledge(msg4, "Attacker")
        print(f"\nAttacker intercepts: {msg4}")
        print(f"MESSAGE: Bob -> Alice (intercepted by Attacker): {{Nb}}K_AB")
        # Alice receives, decrypts, and responds
        self.alice_dys.addKnowledge(msg4, "Alice")
        self.alice_dys.deriveKnowledge("Alice")
        nb_minus_1 = "Nb-1"
        self.alice_dys.addKnowledge(nb_minus_1, "Alice")
        msg5 = f"enc({nb_minus_1},{session_key})"
        self.alice_dys.addKnowledge(msg5, "Alice")
        # attacker intercepts the final message
        self.attacker_dys.addKnowledge(msg5, "Attacker")
        print(f"\nAttacker intercepts: {msg5}")
        print(f"MESSAGE: Alice -> Bob (intercepted by Attacker): {{Nb-1}}K_AB")
        # now the first protocol run is complete, attacker has collected messages
        print("\n--- First protocol run complete, attacker has collected messages ---")
        # ========= Start of the actual attack =========
        print("\nStarting the replay attack...")
        # we assume the attacker has now compromised the session key K_AB
        self.attacker_dys.addKnowledge(session_key, "Attacker")
        print(f"\nAttacker has the compromised session key: {session_key}")
        # attacker can now decrypt msg4 to learn Nb
        attacker_derived = self.attacker_dys.deriveKnowledge("Attacker")
        print(f"\nAttacker has learned both nonces: Na and Nb")
        # reset Bob's knowledge base for the attack scenario
        self.bob_dys = DolevYao()
        for term in [self.alice, self.bob, self.server, self.key_bs]:
            self.bob_dys.addKnowledge(term, "Bob")
        # Attacker replays the old ticket to Bob
        self.bob_dys.addKnowledge(msg3, "Bob")
        print(f"\nAttacker replays old ticket to Bob: {msg3}")
        print(f"MESSAGE: Attacker -> Bob (impersonating Alice): {{K_AB, A}}K_BS")
        # Bob derives the session key (thinking it's fresh)
        self.bob_dys.deriveKnowledge("Bob")
        self.bob_dys.addKnowledge(session_key, "Bob")
        # Bob generates a new nonce for this session
        nb_prime = "Nb'"
        self.bob_dys.addKnowledge(nb_prime, "Bob")
        msg4_prime = f"enc({nb_prime},{session_key})"
        self.bob_dys.addKnowledge(msg4_prime, "Bob")
        self.attacker_dys.addKnowledge(msg4_prime, "Attacker")
        print(f"\nBob sends to Attacker (thinking it's Alice): {msg4_prime}")
        print(f"MESSAGE: Bob -> Attacker (believing it's Alice): {{Nb'}}K_AB")
        # attacker decrypts to get Nb_prime
        self.attacker_dys.deriveKnowledge("Attacker")
        # attacker responds with the correct format (Nb_prime - 1)
        nb_prime_minus_1 = "Nb'-1"
        self.attacker_dys.addKnowledge(nb_prime_minus_1, "Attacker")
        msg5_prime = f"enc({nb_prime_minus_1},{session_key})"
        self.attacker_dys.addKnowledge(msg5_prime, "Attacker")
        self.bob_dys.addKnowledge(msg5_prime, "Bob")
        print(f"\nAttacker sends to Bob: {msg5_prime}")
        print(f"MESSAGE: Attacker -> Bob (impersonating Alice): {{Nb'-1}}K_AB")
        # Bob accepts this response, authentication complete
        bob_derived = self.bob_dys.deriveKnowledge("Bob")
        # verify the success of the attack
        attack_success = (
            na in self.attacker_dys.deriveKnowledge("Attacker") and
            nb in self.attacker_dys.deriveKnowledge("Attacker") and
            nb_prime in self.attacker_dys.deriveKnowledge("Attacker") and
            session_key in self.attacker_dys.deriveKnowledge("Attacker")
        )
        
        return {
            "attack_success": attack_success,
            "bob_belief": "talking to Alice",
            "attacker_knowledge": self.attacker_dys.deriveKnowledge("Attacker"),
            "shared_secrets": [na, nb, nb_prime, session_key]
        }
    
    # Verify the security of the protocol.
    def verifySecurity(self):
        attack_result = self.simulateDenningSaccoAttack()
        
        print("\nSecurity Analysis:")
        print(f"Attack successful: {attack_result['attack_success']}")
        print(f"Bob believes he is {attack_result['bob_belief']}")
        print(f"Secrets known to Attacker: {set(attack_result['shared_secrets']) & attack_result['attacker_knowledge']}")
        
        return {
            "protocol_secure": not attack_result['attack_success'],
            "attack_execution": attack_result
        }

if __name__ == "__main__":
    # verify the Needham-Schroeder protocol
    protocol = NeedhamSchroeder()
    result = protocol.verifySecurity()
    
    # verification result
    if not result["protocol_secure"]:
        print("\nThe protocol is not secure! The adversary has violated the property of the protocol.")
    else:
        print("\nThe protocol is secure:)")