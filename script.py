import hashlib

def compute_sha256_xor(file_path):
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
        
        for i, line in enumerate(lines):
            line = line.strip()  # Supprime les espaces et les sauts de ligne
            if line:  # Ignore les lignes vides
                # Convertir la ligne en bytes
                line_bytes = bytes.fromhex(line)
                
                # Calculer le SHA256 de la ligne
                sha256_hash = hashlib.sha256(line_bytes).digest()
                
                # Effectuer le XOR entre la ligne et le hash SHA256
                xor_result = bytes(a ^ b for a, b in zip(line_bytes, sha256_hash))
                
                # Afficher le résultat en hexadécimal
                print(f"Ligne {i + 1} (XOR): {xor_result.hex()}")
    except FileNotFoundError:
        print(f"Le fichier '{file_path}' n'existe pas.")
    except ValueError:
        print("Erreur : Assurez-vous que les lignes du fichier contiennent des valeurs hexadécimales valides.")

# Chemin vers le fichier signature.txt
file_path = "signature.txt"
compute_sha256_xor(file_path)