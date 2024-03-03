def encrypt(text: str, key: int) -> str:
    if key > 25:
        raise ValueError("Klíč je neplatný")

    result = ""

    for letter in text.upper().replace(" ", ""):
        result += chr((ord(letter) + key - 65) % 26 + 65)

    return result


def decrypt(text: str, key: int) -> str:
    if key > 25:
        raise ValueError("Klíč je neplatný")

    result = ""

    for letter in text.upper().replace(" ", ""):
        result += chr((ord(letter) - key - 65) % 26 + 65)

    return result

if __name__ == "__main__":
    key = 7

    text = input("Zadejte vstupní text: ")
    key = int(input("Zadejte klíč: "))
    enc = encrypt(text, key)
    print(f"Zašifrovaný text s klíčem {key}: {enc}")
    dec = decrypt(enc, key)
    print(f"Dešifrovaný text: {dec}")

    input("Stisknutím ENTERu ukončíte program")
