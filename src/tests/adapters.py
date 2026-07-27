from kyber import CommunicationPartyKEM, Conversion

class NIST_to_CommunicationPartyKEM:
    def __init__(self, parameter_set: str):
        self.kem = CommunicationPartyKEM(parameter_set)
        self.params = self.kem.parameters

    def unpack_ciphertext(self, c_bytes:bytes) -> tuple[bytes, bytes]:
        """
        Convert from NIST raw bytes ciphertext c to CommunicationPartyKEM (c1, c2) format.
        """
        c1_bytes = c_bytes[:self.params.k * self.params.du * 32]
        c2_bytes = c_bytes[self.params.k * self.params.du * 32:]

        return (c1_bytes, c2_bytes)

    def pack_ciphertext(self, ciphertext:tuple[bytes, bytes]) -> bytes:
        """
        Convert from CommunicationPartyKEM (c1, c2) format to NIST raw bytes ciphertext c.
        """
        return ciphertext[0] + ciphertext[1]

    def unpack_encapsulation_key(self, ek_bytes:bytes) -> tuple[list[int], bytes]:
        """
        Convert from NIST raw bytes encapsulation key ek to CommunicationPartyKEM (ro, t_hat) format.
        """

        t_hat_bytes = [ek_bytes[i*384:(i+1)*384] for i in range(self.params.k)]
        t_hat = [Conversion.byte_decode(t_hat_bytes[i], 12) for i in range(self.params.k)]
        t_hat_encoded = Conversion.vector_byte_encode(t_hat, 12)

        ro_bytes = ek_bytes[(self.params.k * 384):]
        ro = [int.from_bytes(ro_bytes[i:i+1], 'little') for i in range(0, len(ro_bytes), 1)]

        return (ro, t_hat_encoded)
        
    def unpack_decapsulation_key(self, dk_bytes:bytes) -> list[list[int]]:
        """
        Convert from NIST raw bytes decapsulation key dk to CommunicationPartyKEM (dk_PKE, ek_PKE, H_ek_bytes, z_bytes) format.
        """
        dk_PKE_bytes = [dk_bytes[i*384:(i+1)*384] for i in range(self.params.k)]
        dk_PKE = [Conversion.byte_decode(dk_PKE_bytes[i], 12) for i in range(self.params.k)]
        dk_PKE_encoded = Conversion.vector_byte_encode(dk_PKE, 12)
        
        ek_PKE_bytes = dk_bytes[(self.params.k * 384):(self.params.k * 768 + 32)]
        ek_PKE = self.unpack_encapsulation_key(ek_PKE_bytes)

        H_ek_bytes = dk_bytes[(self.params.k * 768 + 32):(self.params.k * 768 + 64)]
        z_bytes = dk_bytes[(self.params.k * 768 + 64):]


        return dk_PKE_encoded, ek_PKE, H_ek_bytes, z_bytes