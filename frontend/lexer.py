TOKEN_ROLE = "ROLE"
TOKEN_USER = "USER"
TOKEN_IDENTIFIER = "IDENTIFIER"
TOKEN_EXTENDS = "EXTENDS"
TOKEN_LBRACE = "LBRACE"
TOKEN_RBRACE = "RBRACE"
TOKEN_EQUALS = "EQUALS"
TOKEN_PERMISSIONS = "PERMISSIONS"
TOKEN_ROLES = "ROLES"
TOKEN_COMMA = "COMMA"
TOKEN_LBRACKET = "LBRACKET"
TOKEN_RBRACKET = "RBRACKET"
TOKEN_EOF = "EOF"
TOKEN_MUTEX = "MUTEX"

class Token:
    def __init__(self, type_, value, line):
        self.type = type_
        self.value = value
        self.line = line   

    def __repr__(self):
        return f"{self.type}:{self.value} (line {self.line})"

def lex(file_path):
    tokens = []
    with open(file_path, "r") as f:
        lines = f.readlines()

    for line_num, line in enumerate(lines, start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        line = line.replace("{", " { ").replace("}", " } ") \
                   .replace("=", " = ").replace(",", " , ") \
                   .replace("[", " [ ").replace("]", " ] ")
        parts = line.split()

        for part in parts:
            if part == "role":
                tokens.append(Token(TOKEN_ROLE, part, line_num))
            elif part == "user":
                tokens.append(Token(TOKEN_USER, part, line_num))
            elif part == "extends":
                tokens.append(Token(TOKEN_EXTENDS, part, line_num))
            elif part == "{":
                tokens.append(Token(TOKEN_LBRACE, part, line_num))
            elif part == "}":
                tokens.append(Token(TOKEN_RBRACE, part, line_num))
            elif part == "=":
                tokens.append(Token(TOKEN_EQUALS, part, line_num))
            elif part == "permissions":
                tokens.append(Token(TOKEN_PERMISSIONS, part, line_num))
            elif part == "roles":
                tokens.append(Token(TOKEN_ROLES, part, line_num))
            elif part == "[":
                tokens.append(Token(TOKEN_LBRACKET, part, line_num))
            elif part == "]":
                tokens.append(Token(TOKEN_RBRACKET, part, line_num))
            elif part == ",":
                tokens.append(Token(TOKEN_COMMA, part, line_num))
            elif part == "mutex":
                tokens.append(Token(TOKEN_MUTEX, part, line_num))
            else:
                tokens.append(Token(TOKEN_IDENTIFIER, part, line_num))

    tokens.append(Token(TOKEN_EOF, None, line_num))
    return tokens
