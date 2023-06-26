import secrets

# S-Box and Inverse S-Box lookup tables
S_BOX = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2]
]

INV_S_BOX = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2]
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
def encrypt(plaintext, round_keys, iv):
    state = plaintext

    for key in round_keys[:-1]:
        state ^= iv
        state = s_box_substitution(state)
        state = shift_rows(state)
        state = mix_columns(state)
        iv = state
        state ^= key

    state ^= iv
    state = s_box_substitution(state)
    state = shift_rows(state)
    state ^= round_keys[-1]

    return state

# Decryption
def decrypt(ciphertext, round_keys, iv):
    state = ciphertext

    state ^= round_keys[-1]
    state = inv_shift_rows(state)
    state = inv_s_box_substitution(state)

    for key in reversed(round_keys[:-1]):
        state ^= key
        state = inv_mix_columns(state)
        iv = state
        state = inv_shift_rows(state)
        state = inv_s_box_substitution(state)

    state ^= iv

    return state

# S-Box substitution
def s_box_substitution(state):
    if 0 <= state <= 0xF:
        return (S_BOX[state >> 2][state & 0x3])
    else:
        raise ValueError("Input state is out of range.")

# Inverse S-Box substitution
def inv_s_box_substitution(state):
    return (INV_S_BOX[state >> 2][state & 0x3])

# Shift rows
def shift_rows(state):
    if state is not None:
        return ((state & 0x0C) >> 2) | ((state & 0x03) << 2)
    else:
        raise ValueError("Invalid state value: None")

# Inverse shift rows
def inv_shift_rows(state):
    return ((state & 0x0C) >> 2) | ((state & 0x03) << 2)

# Mix columns
def mix_columns(state):
    return ((state & 0x08) >> 1) | ((state & 0x04) << 1) | (state & 0x03)

# Inverse mix columns
def inv_mix_columns(state):
    return ((state & 0x02) << 1) | ((state & 0x01) << 2) | (state & 0x03)

# CTR mode encryption
def ctr_encrypt(plaintext, key):
    round_keys = key_schedule(key)
    iv = secrets.randbits(4)
    ciphertext = 0

    for i in range(len(str(plaintext))):
        counter = i + 1

# Example usage
plaintext = 0b1010101
key = generate_key()

print("Plaintext:", bin(plaintext))
print("Key:", bin(key))

# Encryption
ciphertext = encrypt(plaintext, key_schedule(key), 0)  # Use IV = 0 for testing purposes
print("Ciphertext:", bin(ciphertext))

# Decryption
decrypted_text = decrypt(ciphertext, key_schedule(key), 0)  # Use IV = 0 for testing purposes
print("Decrypted text:", bin(decrypted_text))
