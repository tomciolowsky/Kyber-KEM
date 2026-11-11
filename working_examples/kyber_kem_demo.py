from kyber import ML_KEM_768, CommunicationPartyKEM

kyber_parameters = ML_KEM_768  # or ML_KEM_512 / ML_KEM_1024 / "ML_KEM_768"

Alice = CommunicationPartyKEM(kyber_parameters)
Bob = CommunicationPartyKEM(kyber_parameters)

public_key, secret_key = Alice.key_generation()

Bob_shared_secret, Bob_ciphertext = Bob.encapsulate(public_key)
Alice_shared_secret = Alice.decapsulate(secret_key, Bob_ciphertext)

assert Alice_shared_secret == Bob_shared_secret, "Shared secrets do not match!"

if Alice_shared_secret == Bob_shared_secret:
    print("Shared secrets match!")