from poems import poems

from kyber import CommunicationPartyPKE, ML_KEM_512, ML_KEM_768, ML_KEM_1024

kyber_parameters = ML_KEM_768 # or ML_KEM_512 or ML_KEM_1024

Alice = CommunicationPartyPKE(kyber_parameters)
Bob = CommunicationPartyPKE(kyber_parameters)

public_key, secret_key = Alice.key_generation_PKE()

for poem in poems:

    Alice_recovered_bytes = b""
    poem_bytes = poem.encode('utf-8')
    for i in range(0, len(poem_bytes), kyber_parameters.n // 8):
        chunk_of_bytes = poem_bytes[i:i + kyber_parameters.n // 8]
        Bob_ciphertext = Bob.encrypt(public_key, chunk_of_bytes)
        Alice_recovered_bytes += Alice.decrypt(secret_key, Bob_ciphertext)
    
    Alice_plaintext_recovered = Alice_recovered_bytes.decode('utf-8', errors='ignore').rstrip('\x00')

    assert Alice_plaintext_recovered == poem, "Recovered plaintext is NOT the same as Original plaintext!"

    print(Alice_plaintext_recovered)
    print("\n\n")