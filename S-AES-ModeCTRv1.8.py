import wave

#S-Box
sBox = [0x9, 0x4, 0xa, 0xb, 0xd, 0x1, 0x8, 0x5,
        0x6, 0x2, 0x0, 0x3, 0xc, 0xe, 0xf, 0x7]

# sBox = [0x9, 0x4, 0xa, 0xb, 0xd, 0x1, 0x8, 0x5,
#         0x6, 0x2, 0x0, 0x3, 0xc, 0xe, 0xf, 0x7,
#         0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]


# Inverse S-Box
sBoxI = [0xa, 0x5, 0x9, 0xb, 0x1, 0x7, 0x8, 0xf,
         0x6, 0x0, 0x2, 0x3, 0xc, 0x4, 0xd, 0xe]


# Round keys: K0 = w0 + w1; K1 = w2 + w3; K2 = w4 + w5
w = [None] * 6


def mult(p1, p2):
    """Multiply two polynomials in GF(2^4)/x^4 + x + 1"""
    p = 0
    while p2:
        if p2 & 0b1:
            p ^= p1
        p1 <<= 1
        if p1 & 0b10000:
            p1 ^= 0b11
        p2 >>= 1
    return p & 0b1111


def intToVec(n):
    """Convert a 2-byte integer into a 4-element vector"""
    return [n >> 12, (n >> 4) & 0xf, (n >> 8) & 0xf, n & 0xf]


def vecToInt(m):
    """Convert a 4-element vector into 2-byte integer"""
    return (m[0] << 12) + (m[2] << 8) + (m[1] << 4) + m[3]


def addKey(s1, s2):
    """Add two keys in GF(2^4)"""
    return [i ^ j for i, j in zip(s1, s2)]


def sub4NibList(sbox, s):
    """Nibble substitution function"""
    return [sbox[e] if e < len(sbox) else 0 for e in s]




def shiftRow(s):
    """ShiftRow function"""
    return [s[0], s[1], s[3], s[2]]


def keyExp(key):
    """Generate the three round keys"""

    def sub2Nib(b):
        """Swap each nibble and substitute it using sBox"""
        return sBox[b >> 4] + (sBox[b & 0x0f] << 4)

    Rcon1, Rcon2 = 0b10000000, 0b00110000
    w[0] = (key & 0xff00) >> 8
    w[1] = key & 0x00ff
    w[2] = w[0] ^ Rcon1 ^ sub2Nib(w[1])
    w[3] = w[2] ^ w[1]
    w[4] = w[2] ^ Rcon2 ^ sub2Nib(w[3])
    w[5] = w[4] ^ w[3]


def encrypt(ptext):
    """Encrypt plaintext block"""

    def mixCol(s):
        return [s[0] ^ mult(4, s[2]), s[1] ^ mult(4, s[3]),
                s[2] ^ mult(4, s[0]), s[3] ^ mult(4, s[1])]

    state = intToVec(((w[0] << 8) + w[1]) ^ ptext)
    state = mixCol(shiftRow(sub4NibList(sBox, state)))
    state = addKey(intToVec((w[2] << 8) + w[3]), state)
    state = shiftRow(sub4NibList(sBox, state))
    return vecToInt(addKey(intToVec((w[4] << 8) + w[5]), state))


def decrypt(ctext):
    """Decrypt ciphertext block"""

    def iMixCol(s):
        return [mult(9, s[0]) ^ mult(2, s[2]), mult(9, s[1]) ^ mult(2, s[3]),
                mult(9, s[2]) ^ mult(2, s[0]), mult(9, s[3]) ^ mult(2, s[1])]

    state = intToVec(((w[4] << 8) + w[5]) ^ ctext)
    state = sub4NibList(sBoxI, shiftRow(state))
    state = iMixCol(addKey(intToVec((w[2] << 8) + w[3]), state))
    state = sub4NibList(sBoxI, shiftRow(state))
    return vecToInt(addKey(intToVec((w[0] << 8) + w[1]), state))


def ctr_encrypt(plaintext, round_keys, nonce):
    """Encrypt plaintext using S-AES in CTR mode"""
    counter = 0
    ciphertext = b""
    for i in range(0, len(plaintext), 2):
        counter += 1
        nonce_counter = nonce + counter.to_bytes(8, 'big')
        keystream = encrypt(int.from_bytes(nonce_counter, 'big'))
        if i + 2 > len(plaintext):
            plaintext_block = plaintext[i:]
            pad_length = 2 - len(plaintext_block)
            plaintext_block += bytes([pad_length] * pad_length)
        else:
            plaintext_block = plaintext[i:i + 2]
        ciphertext_block = bytes([a ^ b for a, b in zip(plaintext_block, keystream.to_bytes(2, 'big'))])
        ciphertext += ciphertext_block
    return ciphertext


def ctr_decrypt(ciphertext, round_keys, nonce):
    """Decrypt ciphertext using S-AES in CTR mode"""
    decrypted_plaintext = ctr_encrypt(ciphertext, round_keys, nonce)

    # Remove padding if present
    if decrypted_plaintext[-1:] == b"\x01":
        decrypted_plaintext = decrypted_plaintext[:-1]

    return decrypted_plaintext



def read_audio(file_path):
    """Read audio file and return the samples as a list"""
    audio = wave.open(file_path, 'rb')
    sample_width = audio.getsampwidth()
    frame_count = audio.getnframes()
    audio_data = audio.readframes(frame_count)
    audio.close()

    samples = []
    for i in range(0, len(audio_data), sample_width):
        sample = int.from_bytes(audio_data[i:i+sample_width], 'little', signed=True)
        samples.append(sample)

    return samples


def write_audio(file_path, samples, sample_width):
    """Write audio file with the provided samples"""
    audio = wave.open(file_path, 'wb')
    audio.setnchannels(1)  # Mono audio
    audio.setsampwidth(sample_width)
    audio.setframerate(44100)  # Sample rate
    audio.writeframes(b''.join(sample.to_bytes(sample_width, 'little', signed=True) for sample in samples))
    audio.close()


def ctr_encrypt_audio(input_file, output_file, round_keys, nonce):
    """Encrypt file using S-AES in CTR mode"""
    counter = 0
    ciphertext = b""

    with open(input_file, 'rb') as file:
        plaintext = file.read()

        for i in range(0, len(plaintext), 2):
            counter += 1
            nonce_counter = nonce + counter.to_bytes(8, 'big')
            keystream = encrypt(int.from_bytes(nonce_counter, 'big'))

            if i + 2 > len(plaintext):
                plaintext_block = plaintext[i:]
                pad_length = 2 - len(plaintext_block)
                plaintext_block += bytes([pad_length] * pad_length)
            else:
                plaintext_block = plaintext[i:i + 2]

            ciphertext_block = bytes([a ^ b for a, b in zip(plaintext_block, keystream.to_bytes(2, 'big'))])
            ciphertext += ciphertext_block

    with open(output_file, 'wb') as file:
        file.write(ciphertext)


def ctr_decrypt_audio(input_file, output_file, round_keys, nonce):
    """Decrypt file using S-AES in CTR mode"""
    counter = 0
    plaintext = b""

    with open(input_file, 'rb') as file:
        ciphertext = file.read()

        for i in range(0, len(ciphertext), 2):
            counter += 1
            nonce_counter = nonce + counter.to_bytes(8, 'big')
            keystream = encrypt(int.from_bytes(nonce_counter, 'big'))

            if i + 2 > len(ciphertext):
                ciphertext_block = ciphertext[i:]
            else:
                ciphertext_block = ciphertext[i:i + 2]

            plaintext_block = bytes([a ^ b for a, b in zip(ciphertext_block, keystream.to_bytes(2, 'big'))])
            plaintext += plaintext_block

    with open(output_file, 'wb') as file:
        file.write(plaintext)
    return plaintext


def brute_force_decrypt_audio(output_file, nonce,input_file,decrypted_file):
    """Brute force attack to decrypt ciphertext in CTR mode"""
    with open(input_file, 'rb') as file:
        plaintext = file.read()
    for key in range(0b0100101011110100, 0b01001010111101011):  # Iterate through all possible keys
        keyExp(key)
        print(f"w::: {w}")
        decrypted_plaintext = ctr_decrypt_audio(output_file,decrypted_file,key, nonce)

        if decrypted_plaintext == plaintext:
            return key
    return None
def brute_force_decrypt_text(ciphertext, nonce):
    """Brute force attack to decrypt ciphertext in CTR mode"""
    for key in range(0, 0b01001010111101011):  # Iterate through all possible keys

        keyExp(key)

        decrypted_plaintext = ctr_decrypt(ciphertext, w, nonce)

        if decrypted_plaintext == plaintext:
            return key
    return None
if __name__ == '__main__':
    plaintext = b"Hello Charbel, it's just a test for the bruteforce attack"
    key = 0b0100101011110101
    nonce = b'\x00' * 8

    keyExp(key)
    ciphertext = ctr_encrypt(plaintext, w, nonce)
    decrypted_plaintext = ctr_decrypt(ciphertext, w, nonce)

    print(f"Plaintext: {plaintext}")
    print(f"Ciphertext: {ciphertext}")
    print(f"Decrypted plaintext: {decrypted_plaintext}")

    # Brute force attack
    recovered_key = brute_force_decrypt_text(ciphertext, nonce)

    if recovered_key is not None:
        print(f"Recovered Key: {recovered_key}")
    else:
        print("Key not found.")

    # Usage example
    input_audio = r"C:\Users\charb\Desktop\Semester 8\info431 - crypto\Project\Audio\RaveMusic.wav"
    encrypted_audio = r"C:\Users\charb\Desktop\Semester 8\info431 - crypto\Project\Audio\encrypted_audio.wav"
    decrypted_audio = r"C:\Users\charb\Desktop\Semester 8\info431 - crypto\Project\Audio\decrypted_audio.wav"
    decrypted_audio_brute_force = r"C:\Users\charb\Desktop\Semester 8\info431 - crypto\Project\Audio\decrypted_audio_brute_force.wav"
    key = 0b0100101011110101
    keyExp(key)
    nonce = b'\x00' * 8

    ctr_encrypt_audio(input_audio, encrypted_audio, key, nonce)
    ctr_decrypt_audio(encrypted_audio, decrypted_audio, key, nonce)

    recovered_key = brute_force_decrypt_audio(encrypted_audio, nonce,input_audio,decrypted_audio_brute_force)

    if recovered_key is not None:
        print(f"Recovered Key: {recovered_key}")
    else:
        print("Key not found.")