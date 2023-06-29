from enum import Enum

class PROTOCOL_MESSAGES(Enum):
    # Protocol messages
    CON_SYN     = b'\x1f\x2f\x3f\x4f\x5f\x6f\x7f\x8f'  # Connection synchronization message
    CON_ENC     = b'\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'  # Connection encryption message
    CON_ENC_OK  = b'\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f'  # Connection ready-to-encryption message
    CON_ENC_NOK = b'\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff'  # Connection not-ready-to-encryption message

def is_proto_message(received_message: bytes) -> str|bool:
    # Check if the received message is a protocol message
    for protocol_message in PROTOCOL_MESSAGES:
        if received_message == protocol_message.value:
            return protocol_message.name
    return False
