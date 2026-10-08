"""Rede de substituição-permutação (SPN) de 80 bits"""

from collections.abc import Sequence

from cipher_base import (
    BLOCK_SIZE,
    NIBBLE_SIZE,
    SPN_ROUNDS,
    permutation,
    sbox_layer,
    spn_round_keys,
    validate_block,
)


NIBBLE_COUNT = BLOCK_SIZE // NIBBLE_SIZE


class SPN80:
    """Rede de substituição-permutação sobre um bloco de 80 bits.
    Cada uma das primeiras rounds - 1 rodadas é XOR com a chave de rodada, camada de S-box e P-box. A última rodada dispensa a P-box, que não acrescentaria nada antes do XOR final, e termina com um XOR de branqueamento, de modo que são consumidas rounds + 1 chaves de rodada.
    """

    def __init__(self, sbox: Sequence[int], pbox: Sequence[int], rounds: int, master_key: int) -> None:
        self.sbox = list(sbox)
        self.pbox = list(pbox)
        self.rounds = rounds
        self.round_keys = spn_round_keys(master_key, rounds)

    @classmethod
    def from_design(cls, design: object) -> "SPN80":
        return cls(design.SBOX, design.SPN_PBOX, SPN_ROUNDS, design.MASTER_KEY)

    def encrypt_block(self, plaintext: int) -> int:
        validate_block(plaintext, "mensagem")
        state = plaintext

        for round_index in range(self.rounds - 1):
            state ^= self.round_keys[round_index]
            state = sbox_layer(state, self.sbox, NIBBLE_COUNT)
            state = permutation(state, self.pbox)

        state ^= self.round_keys[self.rounds - 1]
        state = sbox_layer(state, self.sbox, NIBBLE_COUNT)
        return state ^ self.round_keys[self.rounds]


if __name__ == "__main__":
    import sys

    import my_cipher
    from cipher_base import validate_design

    problems = validate_design(my_cipher)
    if problems:
        print("my_cipher.py ainda não está utilizável:")
        for problem in problems:
            print(f"  - {problem}")
        sys.exit(1)

    empty = "(nenhum byte)"
    block_bytes = BLOCK_SIZE // 8
    messages = []
    for argument in sys.argv[1:] or ["dez bytes!"]:
        data = argument.encode()
        if len(data) > block_bytes:
            print(f"mensagem longa demais: {argument}")
            print(f"o bloco tem {block_bytes} bytes e essa tem {len(data)}")
            print("para mensagens de qualquer tamanho, use ctr.py")
            sys.exit(1)
        messages.append((argument, data))

    cipher = SPN80.from_design(my_cipher)

    print(f"{'cifra:':8s}SPN, {cipher.rounds} rodadas")

    for index, (text, data) in enumerate(messages, start=1):
        block = int.from_bytes(data.ljust(block_bytes, b"\x00"), "big")
        ciphertext = cipher.encrypt_block(block)
        data_hex = f"0x{data.hex()}" if data else empty

        print()
        print(f"mensagem {index}, {len(data)} byte{'' if len(data) == 1 else 's'}")
        print(f"  {'texto':11s}  {text or empty}")
        print(f"  {'hex':11s}  {data_hex}")
        print(f"  {'bloco':11s}  0x{block:0{block_bytes * 2}x}")
        print(f"  {'criptograma':11s}  0x{ciphertext:0{block_bytes * 2}x}")
