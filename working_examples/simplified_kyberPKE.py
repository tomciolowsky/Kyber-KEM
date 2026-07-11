from modules.KyberParameters import SimplifiedKyberParameters
from modules.CommunicationParty import SimplifiedCommunicationParty
from modules.Poems import poems

kyber_parameters = SimplifiedKyberParameters()
Alice = SimplifiedCommunicationParty(kyber_parameters)
Bob = SimplifiedCommunicationParty(kyber_parameters)

Alice_public_key = Alice.generate_public_key()

Bob.A = Alice_public_key[0]
Bob.t = Alice_public_key[1]

for poem in poems:

    Alice_recovered_bytes = b""
    poem_bytes = poem.encode('utf-8')
    for i in range(0, len(poem_bytes), kyber_parameters.n // 8):
        chunk_of_bytes = poem_bytes[i:i + kyber_parameters.n // 8]
        Bob_ciphertext = Bob.encrypt(chunk_of_bytes) 
        Alice_recovered_bytes += Alice.decrypt(Bob_ciphertext)
    
    Alice_plaintext_recovered = Alice_recovered_bytes.decode('utf-8', errors='ignore').rstrip('\x00')

    assert Alice_plaintext_recovered == poem, "Recovered plaintext is NOT the same as Original plaintext!"

    print(Alice_plaintext_recovered)
    print("\n\n")