from aes import AES

BLOCK_SIZE = 16
CHUNK_SIZE = 1024 * 1024  # 1 МБ


def encrypt_file(in_path: str, out_path: str, aes: AES):
    if CHUNK_SIZE % BLOCK_SIZE != 0:
        raise ValueError("CHUNK_SIZE must be multiple of 16")

    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        tail = b""

        while chunk := fin.read(CHUNK_SIZE):
            data = tail + chunk
            full_len = (len(data) // BLOCK_SIZE) * BLOCK_SIZE

            for i in range(0, full_len, BLOCK_SIZE):
                fout.write(aes.encrypt_block(data[i:i + BLOCK_SIZE]))

            tail = data[full_len:]

        if tail:
            tail += b"\x00" * (BLOCK_SIZE - len(tail))
            fout.write(aes.encrypt_block(tail))


def decrypt_file(in_path: str, out_path: str, aes: AES):
    if CHUNK_SIZE % BLOCK_SIZE != 0:
        raise ValueError("CHUNK_SIZE must be multiple of 16")

    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        tail = b""

        while chunk := fin.read(CHUNK_SIZE):
            data = tail + chunk
            full_len = (len(data) // BLOCK_SIZE) * BLOCK_SIZE

            for i in range(0, full_len, BLOCK_SIZE):
                fout.write(aes.decrypt_block(data[i:i + BLOCK_SIZE]))

            tail = data[full_len:]

        if tail:
            raise ValueError("Encrypted file size must be multiple of 16 bytes")