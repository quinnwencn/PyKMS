from PyKCS11 import *
from pycryptoki.defines import *


class Hsm:
    def __init__(self, hsm_lib_path: str, pin: str):
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(hsm_lib_path)
        self.pin = pin

    def generate_key(self, key_id: bytes, label: str):
        slot = self.pkcs11.getSlotList(tokenPresent=True)[0]
        session = self.pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
        session.login(self.pin)

        pubTemplate = [
            (CKA_CLASS, CKO_PUBLIC_KEY),
            (CKA_TOKEN, CK_TRUE),
            (CKA_PRIVATE, CK_FALSE),
            (CKA_MODULUS_BITS, 0x0400),
            (CKA_PUBLIC_EXPONENT, (0x01, 0x00, 0x01)),
            (CKA_ENCRYPT, CK_TRUE),
            (CKA_VERIFY, CK_TRUE),
            (CKA_VERIFY_RECOVER, CK_TRUE),
            (CKA_WRAP, CK_TRUE),
            (CKA_LABEL, label),
            (CKA_ID, key_id),
        ]

        privTemplate = [
            (CKA_CLASS, CKO_PRIVATE_KEY),
            (CKA_TOKEN, CK_TRUE),
            (CKA_PRIVATE, CK_TRUE),
            (CKA_DECRYPT, CK_TRUE),
            (CKA_SIGN, CK_TRUE),
            (CKA_SIGN_RECOVER, CK_TRUE),
            (CKA_UNWRAP, CK_TRUE),
            (CKA_ID, key_id),
        ]

        (pub_key, priv_key) = session.generateKeyPair(pubTemplate, privTemplate)
        print(f"pub: {pub_key}")
        print(f"priv: {priv_key}")

        session.logout()
        session.closeSession()

