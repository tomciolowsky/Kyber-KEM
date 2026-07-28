from kyber import CommunicationPartyKEM, Conversion

class NIST_to_CommunicationPartyKEM:
    def __init__(self, parameter_set:str):
        self.kem = CommunicationPartyKEM(parameter_set)
        self.params = self.kem.parameters

    def unpack_ciphertext(self, c_hex:str) -> tuple[bytes, bytes]:
        """
        Convert ciphertext from NIST upper hex format to CommunicationPartyKEM (c1, c2) format.
        """
        c_bytes = bytes.fromhex(c_hex)
        c1_bytes = c_bytes[:self.params.k * self.params.du * 32]
        c2_bytes = c_bytes[self.params.k * self.params.du * 32:]

        return (c1_bytes, c2_bytes)

    def pack_ciphertext(self, ciphertext:tuple[bytes, bytes]) -> str:
        """
        Convert ciphertext from CommunicationPartyKEM (c1, c2) format to NIST upper hex format.
        """
        return (ciphertext[0] + ciphertext[1]).hex().upper()

    def unpack_encapsulation_key(self, ek_hex:str) -> tuple[list[int], bytes]:
        """
        Convert encapsulation key from NIST upper hex format to CommunicationPartyKEM (ro, t_hat) format.
        """
        ek_bytes = bytes.fromhex(ek_hex)

        t_hat_bytes = [ek_bytes[i*384:(i+1)*384] for i in range(self.params.k)]
        t_hat = [Conversion.byte_decode(t_hat_bytes[i], 12) for i in range(self.params.k)]
        t_hat_encoded = Conversion.vector_byte_encode(t_hat, 12)

        ro_bytes = ek_bytes[(self.params.k * 384):]
        ro = [int.from_bytes(ro_bytes[i:i+1], 'little') for i in range(0, len(ro_bytes), 1)]

        return (ro, t_hat_encoded)

    def pack_encapsulation_key(self, ek:tuple[list[int], bytes]) -> str:
        """
        Convert encapsulation key from CommunicationPartyKEM (ro, t_hat) format to NIST upper hex format.
        """
        ro_bytes = bytes(ek[0])
        t_hat_bytes = ek[1]
        return (t_hat_bytes + ro_bytes).hex().upper()
    
    def unpack_decapsulation_key(self, dk_hex:str) -> list[list[int]]:
        """
        Convert decapsulation key from NIST upper hex format to CommunicationPartyKEM (dk_PKE, ek_PKE, H_ek_bytes, z_bytes) format.
        """
        dk_bytes = bytes.fromhex(dk_hex)
        dk_PKE_bytes = [dk_bytes[i*384:(i+1)*384] for i in range(self.params.k)]
        dk_PKE = [Conversion.byte_decode(dk_PKE_bytes[i], 12) for i in range(self.params.k)]
        dk_PKE_encoded = Conversion.vector_byte_encode(dk_PKE, 12)
        
        ek_PKE_bytes = dk_bytes[(self.params.k * 384):(self.params.k * 768 + 32)]
        ek_PKE = self.unpack_encapsulation_key(ek_PKE_bytes.hex())

        H_ek_bytes = dk_bytes[(self.params.k * 768 + 32):(self.params.k * 768 + 64)]
        z_bytes = dk_bytes[(self.params.k * 768 + 64):]

        return dk_PKE_encoded, ek_PKE, H_ek_bytes, z_bytes

    def pack_decapsulation_key(self, dk:tuple[bytes, tuple[list[int], bytes], bytes, bytes]) -> str:
        """
        Convert decapsulation key from CommunicationPartyKEM (dk_PKE, ek_PKE, H_ek_bytes, z_bytes) format to NIST upper hex format.
        """
        dk_PKE_encoded = dk[0]
        ro, t_hat_encoded = dk[1]
        H_ek_bytes = dk[2]
        z_bytes = dk[3]

        return (dk_PKE_encoded + t_hat_encoded + bytes(ro) + H_ek_bytes + z_bytes).hex().upper()

    def pack_shared_secret(self, K:list[int]) -> str:
        """
        Convert shared secret from CommunicationPartyKEM format to NIST upper hex format.
        """
        return bytearray(K).hex().upper()