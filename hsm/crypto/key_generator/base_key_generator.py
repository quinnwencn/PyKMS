from abc import ABC, abstractmethod


class BaseKeyGenerator(ABC):
    def __init__(self, hsm_lib_path: str, pin: str):
        self.hsm_lib_path = hsm_lib_path
        self.pin = pin

    @abstractmethod
    def generate_key(self, key_id: bytes, label: str, algo:str, key_size: str):
        pass

    # def import_key(self):
