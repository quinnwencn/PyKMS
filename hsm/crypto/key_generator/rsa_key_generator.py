from PyKCS11.LowLevel import *
from PyKCS11 import *

from config import SUPPORTED_RSA_KEY_SIZE
from .base_key_generator import BaseKeyGenerator


class RsaKeyGenerator(BaseKeyGenerator):
    def __init__(self, hsm_lib_path: str, pin: str):
        super().__init__(hsm_lib_path, pin)
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(self.hsm_lib_path)

    def generate_key(self, key_id: bytes, label: str, algo: str, key_type: str):
        key_size = int(key_type)
        if key_size not in SUPPORTED_RSA_KEY_SIZE:
            return None

        slot = self.pkcs11.getSlotList(tokenPresent=True)[0]
        session = self.pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
        session.login(self.pin)

        pub_template = [
            (CKA_CLASS, CKO_PUBLIC_KEY),
            (CKA_TOKEN, CK_TRUE),
            (CKA_PRIVATE, CK_FALSE),
            (CKA_MODULUS_BITS, key_size),
            (CKA_PUBLIC_EXPONENT, (0x01, 0x00, 0x01)),
            (CKA_ENCRYPT, CK_TRUE),
            (CKA_VERIFY, CK_TRUE),
            (CKA_VERIFY_RECOVER, CK_TRUE),
            (CKA_WRAP, CK_TRUE),
            (CKA_LABEL, label),
            (CKA_ID, key_id),
        ]

        priv_template = [
            (CKA_CLASS, CKO_PRIVATE_KEY),
            (CKA_TOKEN, CK_TRUE),
            (CKA_PRIVATE, CK_TRUE),
            (CKA_DECRYPT, CK_TRUE),
            (CKA_SENSITIVE, TRUE),
            (CKA_SIGN, CK_TRUE),
            (CKA_SIGN_RECOVER, CK_TRUE),
            (CKA_UNWRAP, CK_TRUE),
            (CKA_ID, key_id),
        ]

        (pub_key, _) = session.generateKeyPair(pub_template, priv_template)

        session.logout()
        session.closeSession()
        return pub_key
