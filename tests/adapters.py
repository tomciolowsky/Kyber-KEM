from kyber import CommunicationPartyKEM

class NIST_to_CommunicationPartyKEM:
    def __init__(self, parameter_set:str):
        self.kem = CommunicationPartyKEM(parameter_set)
        self.params = self.kem.parameters

    def hex_format(self, data: bytes) -> str:
        """
        Convert bytes to NIST uppercase hex format.
        """
        return data.hex().upper()

    def bytes_format(self, hex_str: str) -> bytes:
        """
        Convert NIST uppercase hex format to bytes.
        """
        return bytes.fromhex(hex_str)