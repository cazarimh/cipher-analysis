"""Primitivas compartilhadas pelas cifras SPN e Feistel de 80 bits"""

from collections.abc import Sequence


BLOCK_SIZE = 80
HALF_SIZE = BLOCK_SIZE // 2
NIBBLE_SIZE = 4
SBOX_ENTRIES = 1 << NIBBLE_SIZE
MASK = (1 << BLOCK_SIZE) - 1
HALF_MASK = (1 << HALF_SIZE) - 1

# O número de rodadas é fixado pela atividade.
SPN_ROUNDS = 4
FEISTEL_ROUNDS = 8

def validate_block(value: int, name: str, width: int = BLOCK_SIZE) -> None:
    if not 0 <= value < (1 << width):
        raise ValueError(f"{name} precisa ser um valor sem sinal de {width} bits")


def sbox_layer(value: int, sbox: Sequence[int], nibble_count: int) -> int:
    """Aplica a mesma S-box a nibble_count nibbles em paralelo, do menos significativo em diante."""
    result = 0
    for nibble_index in range(nibble_count):
        shift = NIBBLE_SIZE * nibble_index
        nibble = (value >> shift) & 0xF
        result |= sbox[nibble] << shift
    return result


def permutation(value: int, pbox: Sequence[int]) -> int:
    """Move o bit da posição origem para a posição pbox[origem]."""
    result = 0
    for source, target in enumerate(pbox):
        result |= ((value >> source) & 1) << target
    return result


def rotl(value: int, bits: int, width: int = BLOCK_SIZE) -> int:
    """Rotaciona value à esquerda em bits posições, dentro de um registrador de width bits."""
    mask = (1 << width) - 1
    value &= mask
    bits %= width
    if bits == 0:
        return value
    return ((value << bits) | (value >> (width - bits))) & mask


def spn_round_keys(master_key: int, rounds: int) -> list[int]:
    """A chave de rodada i é a chave secreta rotacionada i bits à esquerda, com XOR de i."""
    return [rotl(master_key, index) ^ index for index in range(rounds + 1)]


def feistel_subkeys(master_key: int, rounds: int) -> list[int]:
    """A subchave i combina com XOR as duas metades da chave secreta rotacionada i bits à esquerda, e depois faz XOR com o índice da rodada. Assim as duas metades da chave alcançam todas as rodadas."""
    subkeys = []
    for index in range(rounds):
        word = rotl(master_key, index)
        subkeys.append(((word >> HALF_SIZE) ^ (word & HALF_MASK)) ^ index)
    return subkeys


def _is_table_of(table: object, size: int, bound: int) -> bool:
    return (
        isinstance(table, Sequence)
        and not isinstance(table, (str, bytes))
        and len(table) == size
        and all(isinstance(entry, int) and not isinstance(entry, bool) for entry in table)
        and all(0 <= entry < bound for entry in table)
    )


def _is_permutation_of(table: object, size: int) -> bool:
    return _is_table_of(table, size, size) and sorted(table) == list(range(size))


def validate_design(design: object) -> list[str]:
    problems = []
    sbox = getattr(design, "SBOX", None)
    if not _is_table_of(sbox, SBOX_ENTRIES, SBOX_ENTRIES):
        problems.append(
            f"SBOX precisa ter {SBOX_ENTRIES} entradas, cada uma um valor de 0 a {SBOX_ENTRIES - 1} (valores repetidos são permitidos)"
        )

    spn_pbox = getattr(design, "SPN_PBOX", None)
    if not _is_permutation_of(spn_pbox, BLOCK_SIZE):
        problems.append(
            f"SPN_PBOX precisa listar as {BLOCK_SIZE} posições de 0 a {BLOCK_SIZE - 1}, cada uma uma única vez"
        )

    feistel_pbox = getattr(design, "FEISTEL_PBOX", None)
    if not _is_permutation_of(feistel_pbox, HALF_SIZE):
        problems.append(
            f"FEISTEL_PBOX precisa listar as {HALF_SIZE} posições de 0 a {HALF_SIZE - 1}, cada uma uma única vez"
        )

    master_key = getattr(design, "MASTER_KEY", None)
    if not isinstance(master_key, int) or isinstance(master_key, bool) or not 0 <= master_key <= MASK:
        problems.append(f"MASTER_KEY precisa ser um inteiro em [0, 2**{BLOCK_SIZE})")
    elif master_key == 0:
        problems.append(
            "MASTER_KEY ainda é 0, o que faz a chave de rodada i ser igual a i. Escolha uma chave de verdade."
        )

    return problems
