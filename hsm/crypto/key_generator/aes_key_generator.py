import PyKCS11
from PyKCS11.LowLevel import *

from base_key_generator import BaseKeyGenerator
from config import SUPPORTED_AES_KEY_SIZE


class AesKeyGenerator(BaseKeyGenerator):
    def __init__(self, hsm_lib_path: str, pin: str):
        super().__init__(hsm_lib_path, pin)
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(self.hsm_lib_path)

    def generate_key(self, key_id: bytes, label: str, algo: str, key_size: str):
        size = int(key_size)
        if size not in SUPPORTED_AES_KEY_SIZE:
            return None

        slot = self.pkcs11.getSlotList(tokenPresent=True)[0]
        session = self.pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
        session.login(self.pin)

        template = [
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_SENSITIVE, CK_TRUE),
            (CKA_TOKEN, CK_TRUE),
            (CKA_VALUE_LEN, size / 8),
            (CKA_KEY_TYPE, CKK_AES),
            (CKA_LABEL, label),
            (CKA_PRIVATE, CK_TRUE)
        ]

        handle = session.generateKey(template)

        session.logout()
        session.closeSession()
        return handle
