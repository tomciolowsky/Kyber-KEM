from modules.KyberParameters import KyberParameters
from modules.CommunicationParty import CommunicationPartyKEM

kyber_parameters = KyberParameters()
Alice = CommunicationPartyKEM(kyber_parameters)
Bob = CommunicationPartyKEM(kyber_parameters)

Alice_public_key = Alice.key_generation()

Bob.obtain_key(Alice_public_key)

Bob_shared_secret, Bob_ciphertext = Bob.encapsulate()
Alice_shared_secret = Alice.decapsulate(Bob_ciphertext)

assert Alice_shared_secret == Bob_shared_secret, "Shared secrets do not match!"

if Alice_shared_secret == Bob_shared_secret:
    print("Shared secrets match!")