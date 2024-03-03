import random
import numpy as np
from copy import deepcopy


class AES:
    SBOX = (
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    )

    SBOXinv = (
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
    )

    Rcon = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
            0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a)

    Galois = [[2, 3, 1, 1],
              [1, 2, 3, 1],
              [1, 1, 2, 3],
              [3, 1, 1, 2]]

    invGalois = [[14, 11, 13, 9],
                 [9, 14, 11, 13],
                 [13, 9, 14, 11],
                 [11, 13, 9, 14]]
    
    def __init__(self, key: bytes=None) -> None:
        if key is None:
            self.key = self.generate_key()
        else:
            self.key = key

    def _pprint_key(self):
        round_key_print = deepcopy(self.key)
        arr = []
        for j in range(4):
            row_arr = []
            for i in range(4):
                row_arr.append(format(round_key_print[i][j], "x"))
            arr.append(row_arr)

        return np.matrix(arr)

    def _invert_rows_columns(self, block: list[list]):
        row_block = []
        for i in range(4):
            row = []
            for j in range(4):
                row.append(block[j][i])
            row_block.append(row)

        return row_block

    def _bytes_to_block(self, input_bytes: bytes):
        block = []
        for col in range(4):
            row_arr = []
            for row in range(4):
                row_arr.append(input_bytes[4*row + col])
            block.append(row_arr)

        return block

    def _block_to_bytes(self, input_block: list[list]):
        byte_string = b''
        for i in range(4):
            for j in range(4):
                byte_string += int(input_block[j][i]).to_bytes(1, "little")

        return byte_string

    def _gmul(self, a, b):
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            a <<= 1
            if a & 0x100:
                a ^= 0x11b
            b >>= 1
        return p

    def generate_key(self) -> bytes:
        return random.randbytes(16)

    def _generate_subkeys(self):

        subkeys = [self._bytes_to_block(self.key)]

        for key_number in range(10):
            template_key = deepcopy(subkeys[key_number])
            round_key = []

            # RotWord
            main_column = list(np.roll(template_key[3], -1))

            # S-BOX
            for i, byte in enumerate(main_column):
                row = byte >> 4
                col = byte & 0x0F

                main_column[i] = AES.SBOX[16*row + col]

            # XOR a Rcon
            template_column = template_key[0]

            main_column[0] ^= template_column[0]
            main_column[0] ^= AES.Rcon[key_number]
            for i in range(3):
                main_column[i+1] ^= template_column[i+1]

            round_key.append(main_column)

            for i in range(3):
                column = template_key[i+1]
                for byte in range(4):
                    column[byte] ^= round_key[i][byte]
                round_key.append(column)

            subkeys.append(round_key)

        return subkeys

    def _add_round_key(self, block: list[list], key: list[list]):
        for j in range(4):
            for i in range(4):
                block[i][j] ^= key[i][j]

        return block

    def _subbytes(self, block: list[list]):
        for j in range(4):
            for i in range(4):
                byte = block[j][i]
                row = byte >> 4
                col = byte & 0x0F

                block[j][i] = AES.SBOX[16*row + col]

        return block

    def _inv_subbytes(self, block: list[list]):
        for j in range(4):
            for i in range(4):
                byte = block[j][i]
                row = byte >> 4
                col = byte & 0x0F

                block[j][i] = AES.SBOXinv[16*row + col]

        return block

    def _shift_rows(self, block: list[list]):
        block = self._invert_rows_columns(block)

        for i in range(1, 4):
            block[i] = list(np.roll(block[i], -i))

        block = self._invert_rows_columns(block)

        return block

    def _inv_shift_rows(self, block: list[list]):
        block = self._invert_rows_columns(block)

        for i in range(1, 4):
            block[i] = list(np.roll(block[i], i))

        block = self._invert_rows_columns(block)

        return block

    def _mix_columns(self, block: list[list]):
        result_block = []
        for column in range(4):
            result_column = []
            for byte in range(4):
                result_byte = 0
                for mult in range(4):
                    result_byte ^= self._gmul(
                        block[column][mult], AES.Galois[byte][mult])
                result_column.append(result_byte)
            result_block.append(result_column)

        return result_block

    def _inv_mix_columns(self, block: list[list]):
        result_block = []
        for column in range(4):
            result_column = []
            for byte in range(4):
                result_byte = 0
                for mult in range(4):
                    result_byte ^= self._gmul(
                        block[column][mult], AES.invGalois[byte][mult])
                result_column.append(result_byte)
            result_block.append(result_column)

        return result_block

    def encrypt(self, message: bytes):
        if len(message) != 16:
            raise RuntimeError("Nesprávná délka zprávy")
        if len(self.key) != 16:
            raise RuntimeError("Nesprávná délka klíče")

        subkeys = self._generate_subkeys()
        subkey = 0
        message = self._bytes_to_block(message)

        message = self._add_round_key(message, subkeys[subkey])
        subkey += 1

        for _ in range(9):
            message = self._subbytes(message)
            message = self._shift_rows(message)
            message = self._mix_columns(message)
            message = self._add_round_key(message, subkeys[subkey])
            subkey += 1

        message = self._subbytes(message)
        message = self._shift_rows(message)
        message = self._add_round_key(message, subkeys[subkey])

        return self._block_to_bytes(message)

    def decrypt(self, message: bytes):
        if len(message) != 16:
            raise RuntimeError("Nesprávná délka zprávy")
        if len(self.key) != 16:
            raise RuntimeError("Nesprávná délka klíče")

        subkeys = self._generate_subkeys()
        subkeys.reverse()
        subkey = 0
        message = self._bytes_to_block(message)

        message = self._add_round_key(message, subkeys[subkey])
        subkey += 1

        for _ in range(9):
            message = self._inv_shift_rows(message)
            message = self._inv_subbytes(message)
            message = self._add_round_key(message, subkeys[subkey])
            subkey += 1
            message = self._inv_mix_columns(message)

        message = self._inv_shift_rows(message)
        message = self._inv_subbytes(message)
        message = self._add_round_key(message, subkeys[subkey])

        return self._block_to_bytes(message)

if __name__ == "__main__":
    key = b'\x2b\x28\xab\x09\x7e\xae\xf7\xcf\x15\xd2\x15\x4f\x16\xa6\x88\x3c'
    message = b'\x74\x65\x73\x74\x6f\x76\x61\x63\x69\x74\x65\x78\x74\x31\x32\x33'

    print("Message:")
    print(''.join(["{:02x}".format(b) for b in message]))
    print("Key:")
    print(''.join(["{:02x}".format(b) for b in key]))

    aes_module = AES(key)

    print("\nEnc:")
    enc = aes_module.encrypt(message)
    print(''.join(["{:02x}".format(b) for b in enc]))

    dec = aes_module.decrypt(enc)
    print("\nDec:")
    print(''.join(["{:02x}".format(b) for b in dec]))

    print("\nText:")
    print(dec.decode("ascii"))

    if dec == message:
        print("Matching")
