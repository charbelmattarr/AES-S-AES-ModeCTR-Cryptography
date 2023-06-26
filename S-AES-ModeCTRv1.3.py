import secrets

# S-Box and Inverse S-Box lookup tables
S_BOX = [
    [1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14],
    [3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12],
    [5, 4, 7, 6, 1, 0, 3, 2, 13, 12, 15, 14, 9, 8, 11, 10],
    [7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8],
    [9, 8, 11, 10, 13, 12, 15, 14, 1, 0, 3, 2, 5, 4, 7, 6],
    [11, 10, 9, 8, 15, 14, 13, 12, 3, 2, 1, 0, 7, 6, 5, 4],
    [13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2],
    [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    [0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 5, 14, 7],
    [2, 11, 0, 9, 6, 15, 4, 13, 10, 3, 8, 1, 14, 7, 12, 5],
    [4, 13, 6, 15, 2, 11, 0, 9, 12, 5, 14, 7, 10, 3, 8, 1],
    [6, 15, 4, 13, 0, 9, 2, 11, 14, 7, 12, 5, 8, 1, 10, 3],
    [8, 1, 10, 3, 12, 5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15],
    [10, 3, 8, 1, 14, 7, 12, 5, 2, 11, 0, 9, 6, 15, 4, 13],
    [12, 5, 14, 7, 10, 3, 8, 1, 4, 13, 6, 15, 0, 9, 2, 11],
    [14, 7, 12, 5, 8, 1, 10, 3, 6, 15, 4, 13, 2, 11, 0, 9]
]

INV_S_BOX = [
    [8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7],
    [2, 3, 8, 9, 6, 7, 12, 13, 10, 11, 0, 1, 14, 15, 4, 5],
    [4, 5, 6, 7, 0, 1, 2, 3, 14, 15, 8, 9, 12, 13, 10, 11],
    [6, 7, 12, 13, 10, 11, 0, 1, 8, 9, 14, 15, 2, 3, 4, 5],
    [10, 11, 0, 1, 14, 15, 4, 5, 2, 3, 8, 9, 6, 7, 12, 13],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [12, 13, 10, 11, 8, 9, 14, 15, 6, 7, 0, 1, 4, 5, 2, 3],
    [14, 15, 4, 5, 2, 3, 8, 9, 12, 13, 6, 7, 10, 11, 0, 1],
    [1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14],
    [3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12],
    [5, 4, 7, 6, 1, 0, 3, 2, 13, 12, 15, 14, 9, 8, 11, 10],
    [7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8],
    [9, 8, 11, 10, 13, 12, 15, 14, 1, 0, 3, 2, 5, 4, 7, 6],
    [11, 10, 9, 8, 15, 14, 13, 12, 3, 2, 1, 0, 7, 6, 5, 4],
    [13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2],
    [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
]

# Key generation
def generate_key():
    key = secrets.randbits(16)
    return key

# Key schedule
def key_schedule(key):
    round_keys = [key]
    for i in range(3):
        key = (key << 1) % 16 | (key >> 3)
        round_keys.append(key)
    return round_keys

# Encryption
def encrypt(plaintext, round_keys):
    state = plaintext

    for key in round_keys[:-1]:
        state = s_box_substitution(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state ^= key

    state = s_box_substitution(state)
    state = shift_rows(state)
    state ^= round_keys[-1]

    return state

# Decryption
def decrypt(ciphertext, round_keys):
    state = ciphertext

    state ^= round_keys[-1]
    state = inv_shift_rows(state)
    state = inv_s_box_substitution(state)

    for key in reversed(round_keys[:-1]):
        state ^= key
        state = inv_mix_columns(state)
        state = inv_shift_rows(state)
        state = inv_s_box_substitution(state)

    return state

# S-Box substitution
def s_box_substitution(state):

        if 0 <= state <= 0xFFFF:
            return (S_BOX[state >> 12][state >> 8 & 0xF] << 12) | (S_BOX[state >> 4 & 0xF][state & 0xF] << 4)
        else:
            raise ValueError("Input state is out of range.")



# Inverse S-Box substitution
def inv_s_box_substitution(state):
    return (INV_S_BOX[state >> 12][state >> 8 & 0xF] << 12) | (INV_S_BOX[state >> 4 & 0xF][state & 0xF] << 4)

# Shift rows
def shift_rows(state):
    if state is not None:
        return (state & 0xF000) | ((state & 0x0F00) >> 4) | ((state & 0x00F0) << 4) | (state & 0x000F)
    else:
        raise ValueError("Invalid state value: None")

# Inverse shift rows
def inv_shift_rows(state):
    return (state & 0xF000) | (state & 0x00F0) >> 4 | (state & 0x0F00) << 4 | (state & 0x000F)

# Mix columns
def mix_columns(state):
    return (state & 0x8000) | ((state >> 1) & 0x4000) | (state >> 1) & 0x3000 | (state & 0x0800) | (state & 0x0200) >> 1 | (state & 0x0100) << 1 | (state >> 3) & 0x00F0 | (state & 0x000F) << 1

# Inverse mix columns
def inv_mix_columns(state):
    return (state & 0x8000) | ((state >> 1) & 0x4000) | (state >> 1) & 0x3000 | (state & 0x0800) | (state & 0x0200) >> 1 | (state & 0x0100) << 1 | (state >> 1) & 0x00F0 | (state & 0x000F) << 1

# Example usage
key = generate_key()
plaintext = 0b10101010

round_keys = key_schedule(key)
ciphertext = encrypt(plaintext, round_keys)
decrypted_plaintext = decrypt(ciphertext, round_keys)

print("Plaintext:", bin(plaintext))
print("Ciphertext:", bin(ciphertext))
print("Decrypted plaintext:", bin(decrypted_plaintext))
