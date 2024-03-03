def encrypt(text: str, key: str) -> str:
    alphabet = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    key = key.upper()

    result = ""

    for letter in key:
        alphabet.remove(letter)

    alphabet = key + "".join(alphabet)

    # print("Vytvořená abeceda: ", alphabet)

    for letter in text.upper().replace(" ", ""):
        result += alphabet[ord(letter) - 65]

    return result


def decrypt(text: str, key: str) -> str:
    alphabet = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    dec_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    key = key.upper()

    result = ""

    for letter in key:
        alphabet.remove(letter)

    alphabet = key + "".join(alphabet)

    for letter in text:
        result += dec_alphabet[alphabet.index(letter)]

    return result

if __name__ == "__main__":
    key = "chalkos"

    text = input("Zadejte text: ")

    print("Původní text:", text)
    enc = encrypt(text, key)
    print(f"Zašifrovaný text s klíčem {key}:", enc)
    dec = decrypt(enc, key)
    print("Dešifrovaný text:", dec)

    input("Stisknutím ENTERu ukončíte program")
