"""Rede de Feistel de 80 bits"""

from collections.abc import Sequence

from cipher_base import (
    FEISTEL_ROUNDS,
    HALF_MASK,
    HALF_SIZE,
    NIBBLE_SIZE,
    feistel_subkeys,
    permutation,
    sbox_layer,
    validate_block,
)


HALF_NIBBLE_COUNT = HALF_SIZE // NIBBLE_SIZE


class Feistel80:
    """Rede de Feistel sobre um bloco de 80 bits partido em duas metades de 40 bits.
    A rodada i leva (esquerda, direita) em (direita, esquerda ^ F(direita, subchave i)). A troca da última rodada é desfeita na saída, então decifrar é exatamente o mesmo laço com as subchaves na ordem inversa. F não precisa ser inversível, e por isso a função de rodada pode reaproveitar a S-box e a P-box à vontade.
    """

    def __init__(self, sbox: Sequence[int], pbox: Sequence[int], rounds: int, master_key: int) -> None:
        self.sbox = list(sbox)
        self.pbox = list(pbox)
        self.rounds = rounds
        self.subkeys = feistel_subkeys(master_key, rounds)

    @classmethod
    def from_design(cls, design: object) -> "Feistel80":
        return cls(design.SBOX, design.FEISTEL_PBOX, FEISTEL_ROUNDS, design.MASTER_KEY)

    def round_function(self, half: int, subkey: int) -> int:
        """F: XOR com a subchave, substitui dez nibbles, permuta os 40 bits."""
        validate_block(half, "metade", HALF_SIZE)
        state = half ^ subkey
        state = sbox_layer(state, self.sbox, HALF_NIBBLE_COUNT)
        return permutation(state, self.pbox)

    def _run(self, block: int, subkeys: Sequence[int]) -> int:
        left = block >> HALF_SIZE
        right = block & HALF_MASK
        for subkey in subkeys:
            left, right = right, left ^ self.round_function(right, subkey)
        return (right << HALF_SIZE) | left

    def encrypt_block(self, plaintext: int) -> int:
        validate_block(plaintext, "mensagem")
        return self._run(plaintext, self.subkeys)

    def decrypt_block(self, ciphertext: int) -> int:
        validate_block(ciphertext, "criptograma")
        return self._run(ciphertext, list(reversed(self.subkeys)))


if __name__ == "__main__":
    import sys

    import my_cipher
    from cipher_base import BLOCK_SIZE, validate_design

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

    cipher = Feistel80.from_design(my_cipher)

    print(f"{'cifra:':8s}Feistel, {cipher.rounds} rodadas")

    for index, (text, data) in enumerate(messages, start=1):
        block = int.from_bytes(data.ljust(block_bytes, b"\x00"), "big")
        ciphertext = cipher.encrypt_block(block)
        ok = cipher.decrypt_block(ciphertext) == block
        data_hex = f"0x{data.hex()}" if data else empty

        print()
        print(f"mensagem {index}, {len(data)} byte{'' if len(data) == 1 else 's'}")
        print(f"  {'texto':11s}  {text or empty}")
        print(f"  {'hex':11s}  {data_hex}")
        print(f"  {'bloco':11s}  0x{block:0{block_bytes * 2}x}")
        print(f"  {'criptograma':11s}  0x{ciphertext:0{block_bytes * 2}x}")
        print(f"  decifra de volta: {'ok' if ok else 'FALHOU'}")
