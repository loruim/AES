from aes import AES

def encrypt_file(in_path : str, out_path : str, aes : AES): 
    with open(in_path, "rb") as fin, open(out_path, "wb") as fout: 
        while True: 
            block = fin.read(16) 
            if not block: 
                break 
            if len(block) != 16: 
                block = block + (16 - len(block)) * b'\x00' 
            fout.write(aes.encrypt_block(block)) 
                
def decrypt_file(in_path : str, out_path : str, aes : AES): 
    with open(in_path, "rb") as fin, open(out_path, "wb") as fout: 
        while True: 
            block = fin.read(16) 
            if not block: 
                break 
            if len(block) != 16: 
                block = block + (16 - len(block)) * b'\x00' 
            fout.write(aes.decrypt_block(block))