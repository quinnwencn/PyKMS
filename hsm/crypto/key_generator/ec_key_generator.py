from PyKCS11 import *
from PyKCS11.LowLevel import *

from base_key_generator import BaseKeyGenerator
from config import SUPPORTED_EC_KEY_PARAM


class EcKeyGenerator(BaseKeyGenerator):
    def __init__(self, hsm_lib_path: str, pin: str):
        super().__init__(hsm_lib_path, pin)
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(hsm_lib_path)

    def generate_key(self, key_id: bytes, label: str, algo: str, key_type: str):
        if key_type not in SUPPORTED_EC_KEY_PARAM:
            return None

        slot = self.pkcs11.getSlotList(tokenPresent=True)[0]
        session = self.pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
        session.login(self.pin)

        pub_template = [
            (CKA_CLASS, CKO_PUBLIC_KEY),
            (CKA_TOKEN, CK_TRUE),
            (CKA_PRIVATE, CK_FALSE),
            (CKA_KEY_TYPE, CKO_PUBLIC_KEY),
            (CKA_EC_PARAMS, SUPPORTED_EC_KEY_PARAM[key_type]),
            (CKA_VERIFY, CK_TRUE),
            (CKA_VERIFY_RECOVER, CK_TRUE),
            (CKA_ENCRYPT, CK_TRUE),
            (CKA_WRAP, CK_TRUE),
            (CKA_LABEL, label),
            (CKA_ID, key_id),
            (CKA_SENSITIVE, CK_FALSE)
        ]

        priv_template = [
            (CKA_CLASS, CKO_PRIVATE_KEY),
            (CKA_KEY_TYPE, CKO_PRIVATE_KEY),
            (CKA_TOKEN, CK_TRUE),
            (CKA_PRIVATE, CK_TRUE),
            (CKA_SENSITIVE, CK_TRUE),
            (CKA_SIGN, CK_TRUE),
            (CKA_DECRYPT, CK_TRUE),
            (CKA_SIGN_RECOVER, CK_TRUE),
            (CKA_UNWRAP, CK_TRUE),
            (CKA_ID, key_id)
        ]

        (pub_key, _) = session.generateKeyPair(pub_template, priv_template)
        session.logout()
        session.closeSession()
        return pub_key
