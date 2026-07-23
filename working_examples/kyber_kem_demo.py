from kyber import CommunicationPartyKEM, ML_KEM_512, ML_KEM_768, ML_KEM_1024

kyber_parameters = ML_KEM_768 # or ML_KEM_512 or ML_KEM_1024
kyber_parameters_str = "ML_KEM_768" # or "ML_KEM_512" or "ML_KEM_1024"

Alice = CommunicationPartyKEM(kyber_parameters) # or kyber_parameters_str
Bob = CommunicationPartyKEM(kyber_parameters) # or kyber_parameters_str

Alice_public_key = Alice.key_generation()

Bob.obtain_key(Alice_public_key)

Bob_shared_secret, Bob_ciphertext = Bob.encapsulate()
Alice_shared_secret = Alice.decapsulate(Bob_ciphertext)

assert Alice_shared_secret == Bob_shared_secret, "Shared secrets do not match!"

if Alice_shared_secret == Bob_shared_secret:
    print("Shared secrets match!")