"""Modo contador sobre as cifras de bloco de 80 bits: sem padding, nonce novo por mensagem, mensagem de qualquer tamanho."""

import secrets
from cipher_base import BLOCK_SIZE, HALF_MASK, HALF_SIZE, validate_block


BLOCK_BYTES = BLOCK_SIZE // 8
NONCE_HEX_DIGITS = HALF_SIZE // 4


def random_nonce() -> int:
    """Sorteia o nonce de 40 bits de uma mensagem."""
    return secrets.randbits(HALF_SIZE)


def counter_block(nonce: int, counter: int) -> int:
    """Monta o bloco de entrada de 80 bits: um nonce de 40 bits acima de um contador de 40 bits."""
    validate_block(nonce, "nonce", HALF_SIZE)
    validate_block(counter, "contador", HALF_SIZE)
    return (nonce << HALF_SIZE) | counter


def keystream_block(cipher: object, nonce: int, counter: int) -> bytes:
    """Cifra um bloco de contador e devolve seus 10 bytes de keystream."""
    block = cipher.encrypt_block(counter_block(nonce, counter))
    return block.to_bytes(BLOCK_BYTES, "big")


def apply_ctr(cipher: object, nonce: int, data: bytes, initial_counter: int = 0) -> bytes:
    """Faz o XOR de data com o keystream da cifra sob esse nonce.
    A cifra de bloco só é usada no sentido direto, então cifrar e decifrar são a mesma chamada, a mensagem não precisa de padding e o último bloco é simplesmente truncado no que sobrou.
    """
    result = bytearray()

    for offset in range(0, len(data), BLOCK_BYTES):
        chunk = data[offset : offset + BLOCK_BYTES]
        counter = (initial_counter + offset // BLOCK_BYTES) & HALF_MASK
        stream = keystream_block(cipher, nonce, counter)
        result.extend(byte ^ stream[position] for position, byte in enumerate(chunk))

    return bytes(result)


if __name__ == "__main__":
    import sys

    import my_cipher
    from cipher_base import validate_design
    from feistel import Feistel80
    from spn import SPN80

    problems = validate_design(my_cipher)
    if problems:
        print("my_cipher.py ainda não está utilizável:")
        for problem in problems:
            print(f"  - {problem}")
        sys.exit(1)

    empty = "(nenhum byte)"

    args = sys.argv[1:]
    fixed_nonce = None
    if args and args[0] == "--nonce":
        if len(args) != 3:
            print("uso: python3 ctr.py --nonce 0x<40 bits> 'uma mensagem'")
            print("o --nonce vale para uma mensagem só, para repetir uma cifragem já feita")
            sys.exit(1)
        try:
            fixed_nonce = int(args[1], 0)
            validate_block(fixed_nonce, "nonce", HALF_SIZE)
        except ValueError as problem:
            print(f"nonce inválido: {problem}")
            sys.exit(1)
        args = args[2:]

    messages = args or ["Introducao a Criptografia: mensagem de tamanho arbitrario."]
    ciphers = (
        ("SPN", SPN80.from_design(my_cipher)),
        ("Feistel", Feistel80.from_design(my_cipher)),
    )

    print(f"{'cifras:':8s}" + ", ".join(f"{label} com {cipher.rounds} rodadas" for label, cipher in ciphers))

    for index, text in enumerate(messages, start=1):
        message = text.encode()
        message_hex = f"0x{message.hex()}" if message else empty
        nonce = fixed_nonce if fixed_nonce is not None else random_nonce()

        print()
        print(f"mensagem {index}, {len(message)} byte{'' if len(message) == 1 else 's'}")
        print(f"  {'texto':11s}  {text or empty}")
        print(f"  {'hex':11s}  {message_hex}")
        print(f"  {'nonce':11s}  0x{nonce:0{NONCE_HEX_DIGITS}x}")

        checks = []
        for label, cipher in ciphers:
            ciphertext = apply_ctr(cipher, nonce, message)
            ciphertext_hex = f"0x{ciphertext.hex()}" if ciphertext else empty
            print(f"  {label:11s}  {ciphertext_hex}")
            checks.append(f"{label} {'ok' if apply_ctr(cipher, nonce, ciphertext) == message else 'FALHOU'}")
        print(f"  decifra de volta: {', '.join(checks)}")
