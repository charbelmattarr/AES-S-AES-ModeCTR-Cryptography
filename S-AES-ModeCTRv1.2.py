import itertools
from pydub import AudioSegment
import itertools
# AES key expansion constants
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
# AES S-box
S_BOX = [
    0x9, 0x4, 0xA, 0xB,
    0xD, 0x1, 0x8, 0x5,
    0x6, 0x2, 0x0, 0x3,
    0xC, 0xE, 0xF, 0x7
]

mul2 = [
    0x0, 0x2, 0x4, 0x6,
    0x8, 0xA, 0xC, 0xE,
    0x3, 0x1, 0x7, 0x5,
    0xB, 0x9, 0xF, 0xD
]

mul3 = [
    0x0, 0x3, 0x6, 0x5,
    0xC, 0xF, 0xA, 0x9,
    0xB, 0x8, 0xD, 0xE,
    0x7, 0x4, 0x1, 0x2
]

mul9 = [
    0x0, 0x9, 0x1, 0x8,
    0x2, 0xB, 0x3, 0xA,
    0x4, 0xD, 0x5, 0xC,
    0x6, 0xF, 0x7, 0xE
]

mul11 = [
    0x0, 0xB, 0x5, 0xE,
    0xA, 0x1, 0xF, 0x4,
    0x7, 0xC, 0x2, 0x9,
    0xD, 0x6, 0x8, 0x3
]

mul13 = [
    0x0, 0xD, 0x9, 0x4,
    0x1, 0xC, 0x8, 0x5,
    0x2, 0xF, 0xB, 0x6,
    0x3, 0xE, 0xA, 0x7
]

mul14 = [
    0x0, 0xE, 0xC, 0x2,
    0x9, 0x7, 0x5, 0xB,
    0x1, 0xF, 0xD, 0x3,
    0x8, 0x6, 0x4, 0xA
]

def key_expansion(key):
    """
    Expand the encryption key into a set of round keys.

    Args:
        key (bytes): The initial encryption key (16, 24, or 32 bytes).

    Returns:
        list: The list of round keys (each 16 bytes).

    """
    key_size = len(key)
    if key_size not in [16, 24, 32]:
        raise ValueError("Invalid key size. Must be 16, 24, or 32 bytes.")

    # Number of rounds
    if key_size == 16:
        num_rounds = 2
    elif key_size == 24:
        num_rounds = 3
    else:
        num_rounds = 4

    # Key schedule
    round_keys = []

    for i in range(num_rounds):
        round_key = key[i * 8:(i + 1) * 8]
        round_keys.append(round_key)

    return round_keys


def sub_bytes(state):
    """
    Substitute bytes in the state using the S-AES S-box.

    Args:
        state (list): The state matrix.

    """
    for i in range(4):
        for j in range(4):
            state[i][j] = S_BOX[state[i][j]]


def shift_rows(state):
    """
    Shift the rows of the state matrix.

    Args:
        state (list): The state matrix.

    """
    for i in range(1, 4):
        state[i] = state[i][i:] + state[i][:i]


def mix_columns(state):
    """
    Mix the columns of the state matrix.

    Args:
        state (list): The state matrix.

    """
    for j in range(4):
        column = [state[i][j] for i in range(4)]
        state[0][j] = mul2[column[0]] ^ mul3[column[1]] ^ column[2] ^ column[3]
        state[1][j] = column[0] ^ mul2[column[1]] ^ mul3[column[2]] ^ column[3]
        state[2][j] = column[0] ^ column[1] ^ mul2[column[2]] ^ mul3[column[3]]
        state[3][j] = mul2[column[0]] ^ column[1] ^ column[2] ^ mul2[column[3]]


def add_round_key(state, round_key):
    """
    Add the round key to the state matrix.

    Args:
        state (list): The state matrix.
        round_key (bytes): The round key.

    """
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i * 4 + j]



def aes_encrypt_block(block, round_keys):
    state = [[0] * 4 for _ in range(4)]

    # Convert the input block to a 4x4 state matrix
    for i in range(4):
        for j in range(4):
            state[j][i] = block[i + 4 * j]

    # Perform the S-AES encryption rounds
    add_round_key(state, round_keys[0])

    for round_idx in range(1, 4):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[round_idx])

    # Convert the state matrix back to a 16-byte block
    output_block = bytes(state[j][i] for i in range(4) for j in range(4))
    return output_block


def aes_decrypt_block(block, round_keys):
    """
    Decrypt a single block using S-AES.

    Args:
        block (bytes): The ciphertext block to decrypt (16 bytes).
        round_keys (list): The list of round keys.

    Returns:
        bytes: The decrypted plaintext block (16 bytes).
    """
    state = [[0] * 4 for _ in range(4)]

    # Convert the input block to a 4x4 state matrix
    for i in range(4):
        for j in range(4):
            state[i][j] = block[j * 4 + i]  # Fixed indexing here

    # Perform the S-AES decryption rounds in reverse order
    add_round_key(state, round_keys[3])
    inv_shift_rows(state)
    inv_sub_bytes(state)

    for round_idx in range(2, -1, -1):
        add_round_key(state, round_keys[round_idx])
        inv_mix_columns(state)
        inv_shift_rows(state)
        inv_sub_bytes(state)

    add_round_key(state, round_keys[0])

    # Convert the state matrix back to a 16-byte block
    output_block = bytes(state[j][i] for i in range(4) for j in range(4))
    return output_block


def inv_sub_bytes(state):
    """
    Inverse substitution of bytes in the state using the S-AES inverse S-box.

    Args:
        state (list): The state matrix.

    """
    for i in range(4):
        for j in range(4):
            state[i][j] = S_BOX[state[i][j]]


def inv_shift_rows(state):
    """
    Inverse shift the rows of the state matrix.

    Args:
        state (list): The state matrix.

    """
    for i in range(1, 4):
        state[i] = state[i][-i:] + state[i][:-i]



def inv_mix_columns(state):
    """
    Inverse mix the columns of the state matrix.

    Args:
        state (list): The state matrix.

    """
    for j in range(4):
        column = [state[i][j] for i in range(4)]
        state[0][j] = (mul14[column[0]] ^ mul11[column[1]] ^ mul13[column[2]] ^ mul9[column[3]])
        state[1][j] = (mul9[column[0]] ^ mul14[column[1]] ^ mul11[column[2]] ^ mul13[column[3]])
        state[2][j] = (mul13[column[0]] ^ mul9[column[1]] ^ mul14[column[2]] ^ mul11[column[3]])
        state[3][j] = (mul11[column[0]] ^ mul13[column[1]] ^ mul9[column[2]] ^ mul14[column[3]])

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def generate_counter_blocks(nonce, num_blocks):
    """
    Generate counter blocks for CTR mode.

    Args:
        nonce (bytes): The nonce value.
        num_blocks (int): The number of counter blocks to generate.

    Returns:
        list: The list of counter blocks.

    """
    counter_blocks = []
    for i in range(num_blocks):
        counter = nonce + i.to_bytes(8, 'big')
        counter_blocks.append(counter)
    return counter_blocks



def ctr_encrypt(plaintext, round_keys, nonce):
    """
    Encrypt the plaintext using AES-CTR mode.

    Args:
        plaintext (bytes): The plaintext to encrypt.
        round_keys (list): The round keys for AES.
        nonce (bytes): The nonce value.

    Returns:
        bytes: The ciphertext.
    """
    ciphertext = b""
    num_blocks = (len(plaintext) + 15) // 16  # Number of counter blocks needed
    counter_blocks = generate_counter_blocks(nonce, num_blocks)

    for i in range(num_blocks):
        counter_block = aes_encrypt_block(counter_blocks[i], round_keys)
        encrypted_block = xor_bytes(plaintext[i * 16:(i + 1) * 16], counter_block)
        ciphertext += encrypted_block

    return ciphertext

def ctr_decrypt(ciphertext, round_keys, nonce):
    """
    Decrypt the ciphertext using AES-CTR mode.

    Args:
        ciphertext (bytes): The ciphertext to decrypt.
        round_keys (list): The list of round keys.
        nonce (bytes): The nonce value.

    Returns:
        bytes: The plaintext.
    """
    plaintext = b""
    num_blocks = (len(ciphertext) + 15) // 16  # Number of counter blocks needed
    counter_blocks = generate_counter_blocks(nonce, num_blocks)

    for i in range(num_blocks):
        counter_block = aes_encrypt_block(counter_blocks[i], round_keys)
        decrypted_block = xor_bytes(ciphertext[i * 16:(i + 1) * 16], counter_block)
        plaintext += decrypted_block

    return plaintext

#Audio



# AES operations and functions

# Add the required AES operations and functions here


def encrypt_audio(audio_file, encryption_key, nonce):
    # Load the audio file
    audio = AudioSegment.from_file(audio_file)

    # Convert the audio data to bytes
    audio_data = audio.export(format="raw").read()

    # Encrypt the audio data using AES-CTR mode
    ciphertext = ctr_encrypt(audio_data, round_keys, nonce)

    # Convert the ciphertext back to AudioSegment
    encrypted_audio = AudioSegment(ciphertext, frame_rate=audio.frame_rate, sample_width=audio.sample_width,
                                   channels=audio.channels)

    return encrypted_audio


def decrypt_audio(encrypted_audio, encryption_key, nonce):
    # Convert the encrypted audio data to bytes
    encrypted_data = encrypted_audio.export(format="raw").read()

    # Decrypt the encrypted audio data using AES-CTR mode
    plaintext = ctr_decrypt(encrypted_data, round_keys, nonce)

    # Convert the plaintext back to AudioSegment
    decrypted_audio = AudioSegment(plaintext, frame_rate=encrypted_audio.frame_rate,
                                   sample_width=encrypted_audio.sample_width, channels=encrypted_audio.channels)

    return decrypted_audio

def brute_force_attack(ciphertext):
    key_length = 16  # Assuming a 128-bit AES key
    possible_keys = itertools.product(range(256), repeat=key_length)

    for key in possible_keys:
        round_keys = key_expansion(bytes(key))
        decrypted_data = aes_decrypt_block(ciphertext, round_keys)

        # Perform analysis on the decrypted data
        # Check for patterns, meaningful text, etc.

        # Example: Check if the decrypted data contains a known string
        if b"Hello" in decrypted_data:
            print("Possible key found:", key)
            break


# Example usage

encryption_key = b'\x00' * 16  # 16-byte encryption key
round_keys = key_expansion(encryption_key)

plaintext = b"Hello Charbel, it's just a test for the bruteforce attack"  # Example plaintext
nonce = b'\x00' * 8  # 8-byte nonce

ciphertext = ctr_encrypt(plaintext, round_keys, nonce)
decrypted_plaintext = ctr_decrypt(ciphertext, round_keys, nonce)

print(f"Plaintext: {plaintext}")
print(f"Ciphertext: {ciphertext}")
print(f"Decrypted plaintext: {decrypted_plaintext}")



# Usage
# ciphertext = b"\x12\x34\x56\x78..."  # Replace with your ciphertext
# brute_force_attack(ciphertext)
## Audio example

# Example usage

encryption_key = b'\x00' * 16  # 16-byte encryption key
round_keys = key_expansion(encryption_key)

nonce = b'\x00' * 8  # 8-byte nonce

audio_file = r"C:\Users\charb\Desktop\Semester 8\info431 - crypto\Project\Audio\RaveMusic.wav"  # Path to the audio file

print("after audio")
# Encrypt the audio
encrypted_audio = encrypt_audio(audio_file, encryption_key, nonce)
print("after encrypted audio")
# Save the encrypted audio to a file
encrypted_audio.export(r"C:\Users\charb\Desktop\Semester 8\info431 - crypto\Project\Audio\encrypted_audio.wav", format="wav")

print("after encrypted export audio")
# Decrypt the encrypted audio
decrypted_audio = decrypt_audio(encrypted_audio, encryption_key, nonce)
print("after decrypt audio")
# Save the decrypted audio to a file
decrypted_audio.export(r"C:\Users\charb\Desktop\Semester 8\info431 - crypto\Project\Audio\decrypted_audio.wav", format="wav")
print("after decrypt export audio")