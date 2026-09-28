"""Construye `data/corpus.txt`, el diccionario de contraseñas comunes con ranking.

Por qué es un script y no un archivo versionado: el corpus público pesa varios
MB y no tiene sentido en un repositorio. Se genera en el primer arranque, y su
sha256 se publica en /api/policy para que un análisis siga siendo reproducible.

La semilla es una lista de contraseñas realmente usadas, en orden aproximado de
frecuencia. La expansión añade las mutaciones que dominan las fugas reales: el
mismo término con un año, un signo o sustituciones l33t. Eso es justo lo que un
atacante automatizado prueba primero.

Uso:  python scripts/build_corpus.py
"""

from __future__ import annotations

import os
import sys

# Frecuencia aproximada descendente. Las primeras entradas son las que un
# ataque de diccionario acierta casi siempre, y por eso dominan la estimación.
SEED: tuple[str, ...] = (
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234",
    "111111", "1234567", "dragon", "123123", "baseball", "abc123", "football",
    "monkey", "letmein", "696969", "shadow", "master", "666666", "qwertyuiop",
    "123321", "mustang", "1234567890", "michael", "654321", "pussy", "superman",
    "1qaz2wsx", "7777777", "fuckyou", "121212", "000000", "qazwsx", "123qwe",
    "killer", "trustno1", "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter",
    "buster", "soccer", "harley", "batman", "andrew", "tigger", "sunshine",
    "iloveyou", "fuckme", "2000", "charlie", "robert", "thomas", "hockey",
    "ranger", "daniel", "starwars", "klaster", "112233", "george", "asshole",
    "computer", "michelle", "jessica", "pepper", "1111", "zxcvbn", "555555",
    "11111111", "131313", "freedom", "777777", "pass", "fuck", "maggie", "159753",
    "aaaaaa", "ginger", "princess", "joshua", "cheese", "amanda", "summer",
    "love", "ashley", "6969", "nicole", "chelsea", "biteme", "matthew", "access",
    "yankees", "987654321", "dallas", "austin", "thunder", "taylor", "matrix",
    "william", "corvette", "hello", "martin", "heather", "secret", "merlin",
    "diamond", "1234qwer", "gfhjkm", "hammer", "silver", "222222", "88888888",
    "anthony", "justin", "test", "bailey", "q1w2e3r4t5", "patrick", "internet",
    "scooter", "orange", "11111", "golfer", "cookie", "richard", "samantha",
    "bigdog", "guitar", "jackson", "whatever", "mickey", "chicken", "sparky",
    "snoopy", "maverick", "phoenix", "camaro", "peanut", "morgan", "welcome",
    "falcon", "andrea", "joshua", "goober", "carlos", "toyota", "patrick",
    "hannah", "dakota", "maggie", "love", "biteme", "buster", "thomas",
    # Español y términos frecuentes en el entorno del proyecto
    "contrasena", "contraseña", "clave", "secreto", "juan", "maria", "pedro",
    "ana", "carlos", "julieta", "futbol", "estrella", "perro", "gato", "mexico",
    "barcelona", "realmadrid", "amor", "cristina", "alejandro", "hola", "adios",
    "quiere", "familia", "casa", "tierra", "mexico1", "america", "nino", "ano",
    "pablo", "sofia", "laura", "andrea", "diego", "luis", "elena", "oscar",
    "qwert", "asdf", "zxcv", "147258369", "963852741", "741852963", "159357",
    "qwerty1", "abc1234", "123abc", "a123456", "123456a", "1q2w3e", "qwe123",
    "1qazxsw2", "zaq12wsx", "asdfghjkl", "qazxsw", "zaq1", "passw0rd", "p@ssw0rd",
    "pa$$word", "p@$$w0rd", "pa55word", "123qweasd", "q1w2e3", "1q2w3e4r",
    "qweasdzxc", "qazwsxedc", "zaq1xsw2", "1q2w3e4r5t6", "qazxswedc",
    "trustno1!", "welcome1", "admin", "admin123", "administrator", "root",
    "toor", "user", "usuario", "passw0rd!", "letmein!", "changeme", "temp",
    "temp123", "default", "guest", "login", "qwerty12", "qwerty123", "asdf1234",
    "1234abcd", "abcd1234", "password1", "password12", "password123", "pass1234",
    "p@ssword", "password!", "p455w0rd", "iloveu", "lovely", "amanda1",
    "nicole1", "jessica1", "ashley1", "michelle1", "samantha1", "daniel1",
    "matthew1", "andrew1", "joshua1", "james1", "robert1", "william1",
    "richard1", "george1", "charles1", "thomas1", "christopher", "david",
    "michael1", "jennifer1", "jordan23", "superman1", "batman1", "spiderman",
    "pokemon", "minecraft", "naruto", "starwars1", "gandalf", "frodo",
    "sauron", "goku", "pikachu", "sonic", "mario", "zelda", "link1",
    "counter", "strike", "valorant", "fortnite", "apex", "overwatch",
)

_L33T = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7", "l": "|"}


def _mutations(word: str, limit: int) -> list[str]:
    """Variantes típicas de una contraseña filtrada."""
    out: list[str] = []
    if len(word) < 3:
        return out

    out.append(word.capitalize())
    out.append(word.upper())

    for suffix in ("1", "!", "12", "123", "2024", "2025", "2026", "@", "#", "0"):
        out.append(word + suffix)
    for prefix in ("1", "!", "el", "la"):
        out.append(prefix + word)

    if len(word) <= 10:
        for original, replacement in _L33T.items():
            if original in word.lower():
                out.append(word.lower().replace(original, replacement))
                out.append(word.lower().replace(original, replacement) + "1")

    return out[:limit]


def build() -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()

    def push(value: str) -> None:
        token = value.strip()
        if not token:
            return
        key = token.lower()
        if key not in seen:
            seen.add(key)
            ordered.append(token)

    for seed in SEED:
        push(seed)
    for seed in SEED:
        for variant in _mutations(seed, 14):
            push(variant)
    return ordered


def main() -> int:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target = os.path.join(root, "data", "corpus.txt")
    os.makedirs(os.path.dirname(target), exist_ok=True)

    words = build()
    with open(target, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("# PassGuard Lab - Diccionario de contrasenas comunes con ranking.\n")
        handle.write("# Una contrasena por linea. El numero de linea es el ranking.\n")
        handle.write("# Generado por scripts/build_corpus.py. No editar a mano.\n")
        for word in words:
            handle.write(word + "\n")

    sys.stdout.write(f"escritas {len(words)} entradas en {target}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
