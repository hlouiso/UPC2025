import hashlib

def compute_sha256_xor(file_path):
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
        
        for i, line in enumerate(lines):
            line = line.strip()
            if line:
                line_bytes = bytes.fromhex(line)
                
                sha256_hash = hashlib.sha256(line_bytes).digest()
                
                xor_result = bytes(a ^ b for a, b in zip(line_bytes, sha256_hash))
                
                print(f"Ligne {i + 1} (XOR): {xor_result.hex()}")
    except FileNotFoundError:
        print(f"Le fichier '{file_path}' n'existe pas.")
    except ValueError:
        print("Erreur : Assurez-vous que les lignes du fichier contiennent des valeurs hexadécimales valides.")

file_path = "signature.txt"
compute_sha256_xor(file_path)