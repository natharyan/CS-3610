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
        # handle public keys: pk(key)
        elif term.startswith("pk("):
            return ("pk", [term[3:-1]])
        # handle inverse keys: inv(key)
        elif term.startswith("inv("):
            return ("inv", [term[4:-1]])
        # basic term (agent, nonce, key)
        else:
            return ("basic", [term])
    
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
        # if we can't parse properly, return as basic
        return ("basic", [content])
    
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
    def add_knowledge(self, term, agent=""):
        print(f"Adding knowledge to {agent}'s knowledge base: {term}")
        if isinstance(term, str):
            self.knowledge.add(term)
        else:
            self.knowledge.add(str(term))
    # Compute all terms that can be derived from the current knowledge.
    def derive_knowledge(self, agent=""):
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
                    # check if we have the inverse key
                    key_term = Term(key)
                    if key_term.type == "pk" and f"inv({key_term.components[0]})" in Y:
                        if msg not in Y:
                            print("Adding decrypted message:", msg)
                            Z.add(msg)
                    elif f"inv({key})" in Y:
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
            elif term.type in ["pk", "inv"]:
                subterms.add(term.components[0])
        return subterms
    
    # check if the target term can be derived from current knowledge.
    def can_derive(self, target):
        derived = self.derive_knowledge()
        return target in derived

# Implement the Needham-Schroeder Public Key protocol and verify its security.
class NeedhamSchroeder:
    def __init__(self):
        print("Initializing the Needham-Schroeder protocol (reference: Wikipedia)...")
        # define agents
        self.alice = "A"
        self.bob = "B"
        self.impostor = "I"
        # define keys
        self.pk_a = f"pk({self.alice})"
        self.pk_b = f"pk({self.bob})"
        self.pk_i = f"pk({self.impostor})"
        self.sk_a = f"inv({self.alice})"
        self.sk_b = f"inv({self.bob})"
        self.sk_i = f"inv({self.impostor})"
        # define knowledge bases
        self.alice_dys = DolevYao()
        self.bob_dys = DolevYao()
        self.impostor_dys = DolevYao()
        # initialize knowledge
        self._init_knowledge()
    # initialize the knowledge of all agents.
    def _init_knowledge(self):
        print("\nInitializing knowledge for all agents...")
        # Alice's knowledge
        for term in [self.alice, self.bob, self.impostor, self.pk_a, self.pk_b, self.pk_i, self.sk_a]:
            self.alice_dys.add_knowledge(term, "Alice")
        # Bob's knowledge
        for term in [self.alice, self.bob, self.impostor, self.pk_a, self.pk_b, self.pk_i, self.sk_b]:
            self.bob_dys.add_knowledge(term, "Bob")
        # Impostor's knowledge
        for term in [self.alice, self.bob, self.impostor, self.pk_a, self.pk_b, self.pk_i, self.sk_i]:
            self.impostor_dys.add_knowledge(term, "Impostor")
        print("\nKnowledge bases:")
        print("Alice's knowledge:", self.alice_dys.knowledge)
        print("Bob's knowledge:", self.bob_dys.knowledge)
        print("Impostor's knowledge:", self.impostor_dys.knowledge)

    # simulate the normal Needham-Schroeder protocol.
    def simulate_protocol(self):
        # print("\nSimulating normal Needham-Schroeder protocol...")
        # Step 1: Alice generates nonce Na and sends to Bob
        na = "Na"
        self.alice_dys.add_knowledge(na, "Alice")
        msg1 = f"enc(pair({self.alice},{na}),{self.pk_b})"
        self.alice_dys.add_knowledge(msg1, "Alice")
        self.bob_dys.add_knowledge(msg1, "Bob")
        # print(f"\nAlice sends to Bob: {msg1}")
        # Bob can derive Alice's name and Na
        bob_derived = self.bob_dys.derive_knowledge("Bob")
        assert na in bob_derived, "Bob should be able to learn Na"
        # Step 2: Bob generates nonce Nb and sends to Alice
        nb = "Nb"
        self.bob_dys.add_knowledge(nb, "Bob")
        msg2 = f"enc(pair({na},{nb}),{self.pk_a})"
        self.bob_dys.add_knowledge(msg2, "Bob")
        self.alice_dys.add_knowledge(msg2, "Alice")
        # print(f"\nBob sends to Alice: {msg2}")
        # Alice can derive Nb
        alice_derived = self.alice_dys.derive_knowledge("Alice")
        assert nb in alice_derived, "Alice should be able to learn Nb"
        # Step 3: Alice confirms by sending Nb back
        msg3 = f"enc({nb},{self.pk_b})"
        self.alice_dys.add_knowledge(msg3, "Alice")
        self.bob_dys.add_knowledge(msg3, "Bob")
        # print(f"\nAlice sends to Bob: {msg3}")
        
        return {
            "alice_knowledge": self.alice_dys.derive_knowledge("Alice"),
            "bob_knowledge": self.bob_dys.derive_knowledge("Bob"),
            "shared_secrets": [na, nb]
        }
    
    # Simulate the man-in-the-middle attack on the protocol
    def simulate_denning_sacco_attack(self):
        print("\nSimulating man-in-the-middle attack...")
        # Step 1: Alice initiates a session with Impostor I (thinking it's Bob)
        na = "Na"
        self.alice_dys.add_knowledge(na, "Alice")
        msg1 = f"enc(pair({self.alice},{na}),{self.pk_i})"  # Alice sends to Impostor
        self.alice_dys.add_knowledge(msg1, "Alice")
        print(f"\nAlice sends to Impostor: {msg1}")
        self.impostor_dys.add_knowledge(msg1, "Impostor")
        
        # impostor decrypts and learns Na
        impostor_derived = self.impostor_dys.derive_knowledge("Impostor")
        assert na in impostor_derived, "Impostor should learn Na"
        
        # Step 2: Impostor relays message to Bob, pretending to be Alice
        msg1_attack = f"enc(pair({self.alice},{na}),{self.pk_b})"
        self.impostor_dys.add_knowledge(msg1_attack, "Impostor")
        print(f"\nImpostor relays to Bob (pretending to be Alice): {msg1_attack}")
        self.bob_dys.add_knowledge(msg1_attack, "Bob")
        
        # Bob derives Alice's name and Na
        bob_derived = self.bob_dys.derive_knowledge("Bob")
        assert na in bob_derived, "Bob should learn Na"
        
        # Step 3: Bob responds with Na, Nb
        nb = "Nb"
        self.bob_dys.add_knowledge(nb, "Bob")
        msg2 = f"enc(pair({na},{nb}),{self.pk_a})"  # Bob responds to "Alice"
        self.bob_dys.add_knowledge(msg2, "Bob")
        print(f"\nBob sends to Impostor (thinking it's Alice): {msg2}")
        self.impostor_dys.add_knowledge(msg2, "Impostor")
        
        # Step 4: Impostor relays Bob's response to Alice
        msg2_attack = f"enc(pair({na},{nb}),{self.pk_a})"
        self.impostor_dys.add_knowledge(msg2_attack, "Impostor")
        print(f"\nImpostor relays to Alice: {msg2_attack}")
        self.alice_dys.add_knowledge(msg2_attack, "Alice")
        
        # Alice derives Nb
        alice_derived = self.alice_dys.derive_knowledge("Alice")
        assert nb in alice_derived, "Alice should learn Nb"
        
        # Step 5: Alice confirms by sending Nb back to Impostor
        msg3 = f"enc({nb},{self.pk_i})"  # Alice sends to Impostor
        print(f"\nAlice sends to Impostor: {msg3}")
        self.alice_dys.add_knowledge(msg3, "Alice")
        self.impostor_dys.add_knowledge(msg3, "Impostor")
        
        # Step 6: Impostor relays confirmation to Bob
        msg3_attack = f"enc({nb},{self.pk_b})"
        self.impostor_dys.add_knowledge(msg3_attack, "Impostor")
        print(f"\nImpostor relays to Bob: {msg3_attack}")
        self.bob_dys.add_knowledge(msg3_attack, "Bob")
        
        print("\nConfirming knowledge after the attack...")
        # attack verification
        attack_success = (
            na in self.impostor_dys.derive_knowledge("Impostor") and
            nb in self.impostor_dys.derive_knowledge("Impostor")
        )
        
        return {
            "attack_success": attack_success,
            "alice_belief": "talking to Bob",
            "bob_belief": "talking to Alice",
            "impostor_knowledge": self.impostor_dys.derive_knowledge("Impostor"),
            "shared_secrets": [na, nb]
        }
    # Verify the security of the protocol.
    def verify_security(self):
        # print("\nSimulating normal protocol execution...")
        # normal_result = self.simulate_protocol()
        
        attack_result = self.simulate_denning_sacco_attack()
        
        print("\nSecurity Analysis:")
        print(f"Attack successful: {attack_result['attack_success']}")
        print(f"Alice believes she is {attack_result['alice_belief']}")
        print(f"Bob believes he is {attack_result['bob_belief']}")
        print(f"Secrets known to Impostor: {set(attack_result['shared_secrets']) & attack_result['impostor_knowledge']}")
        
        return {
            "protocol_secure": not attack_result['attack_success'],
            # "normal_execution": normal_result,
            "attack_execution": attack_result
        }

if __name__ == "__main__":
    # verify the Needham-Schroeder protocol
    protocol = NeedhamSchroeder()
    result = protocol.verify_security()
    
    # verification result
    if not result["protocol_secure"]:
        print("\nThe protocol is not secure! The adversary has violated the property of the protocol.")
    else:
        print("\nThe protocol is secure:)")