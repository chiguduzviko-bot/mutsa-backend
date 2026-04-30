import hashlib


def sha256_hash_file(file_stream, chunk_size=8192):
    hasher = hashlib.sha256()
    while True:
        chunk = file_stream.read(chunk_size)
        if not chunk:
            break
        hasher.update(chunk)
    file_stream.seek(0)
    return hasher.hexdigest()
