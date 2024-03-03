def encrypt(text: str, key: int) -> str:
    grid = [[" " for _ in range(len(text))] for _ in range(key)]

    result = ""

    direction = True
    row = 0

    for i, letter in enumerate(text):
        grid[row][i] = letter

        if direction:
            row += 1
        else:
            row -= 1

        if row == 0 or row == key-1:
            direction = not direction

    for i in grid:
        result += "".join([j for j in i if j != " "])

    return result


def decrypt(text: str, key: int) -> str:
    grid = [[" " for _ in range(len(text))] for _ in range(key)]

    result = ""

    direction = True
    row = 0

    for i in range(len(text)):
        grid[row][i] = "x"

        if direction:
            row += 1
        else:
            row -= 1

        if row == 0 or row == key-1:
            direction = not direction

    encrypt_index = 0
    for i, row in enumerate(grid):
        for j, position in enumerate(row):
            if position == "x":
                grid[i][j] = text[encrypt_index]
                encrypt_index += 1

    direction = True
    row = 0

    for i in range(len(text)):
        result += grid[row][i]

        if direction:
            row += 1
        else:
            row -= 1

        if row == 0 or row == key-1:
            direction = not direction

    return result

if __name__ == "__main__":
    text = input("Zadejte vstupní text: ")
    key = int(input("Zadejte klíč: "))

    print("Původní text:", text)
    enc = encrypt(text, key)
    print(f"Zašifrovaný text s klíčem {key}:", enc)
    dec = decrypt(enc, key)
    print("Dešifrovaný text:", dec)

    input("Stisknutím ENTERu ukončíte program")
