from core.symbol_table import SymbolTable
from core.model import ASTNode
from frontend.lexer import (
    lex,
    TOKEN_ROLE, TOKEN_USER, TOKEN_IDENTIFIER,
    TOKEN_EXTENDS, TOKEN_LBRACE, TOKEN_RBRACE,
    TOKEN_EQUALS, TOKEN_PERMISSIONS, TOKEN_ROLES,
    TOKEN_LBRACKET, TOKEN_RBRACKET, 
    TOKEN_MUTEX,
    TOKEN_EOF
)
def parse_policy(file_path):
    tokens = lex(file_path)
    table = SymbolTable()
    ast_nodes = []
    syntax_errors = []

    i = 0
    n = len(tokens)

    def current():
        if i < n:
            return tokens[i]
        return tokens[-1]

    def advance():
        nonlocal i
        if i < n:
            i += 1
        return current()

    def add_error(message):
        if message not in syntax_errors:
            syntax_errors.append(message)

    def expect(token_type, message, line):
        if current().type != token_type:
            add_error(f"[SYNTAX ERROR] Line {line}: {message}")
            return False
        return True

    while i < n:
        tok = current()

        if tok.type == TOKEN_EOF:
            break

        if tok.type == TOKEN_ROLE:

            role_line = tok.line
            advance()

            if not expect(TOKEN_IDENTIFIER, "Expected role name", role_line):
                advance()
                continue

            role_name = current().value
            advance()

            table.add_role(role_name, role_line)
            role_obj = table.get_role(role_name)
            node = ASTNode("Role", role_name)

            if current().type == TOKEN_EXTENDS:
                advance()
                if expect(TOKEN_IDENTIFIER,
                          f"Role '{role_name}' missing parent role name",
                          role_line):
                    parent = current().value
                    role_obj.add_parent(parent)
                    node.parents.append(parent)
                    advance()

            if not expect(TOKEN_LBRACE,
                          f"Role '{role_name}' missing '{{'",
                          role_line):
                while current().type not in [TOKEN_LBRACE, TOKEN_EOF]:
                    advance()

            if current().type == TOKEN_LBRACE:
                advance()

            missing_block_close = False

            while current().type not in [TOKEN_RBRACE, TOKEN_EOF]:

                if current().type in [TOKEN_ROLE, TOKEN_USER]:
                    add_error(
                        f"[SYNTAX ERROR] Line {role_line}: "
                        f"Role '{role_name}' missing '}}'"
                    )
                    missing_block_close = True
                    break

                if current().type == TOKEN_PERMISSIONS:

                    perm_line = current().line
                    advance()

                    if not expect(TOKEN_EQUALS,
                                  f"Role '{role_name}' permissions missing '='",
                                  perm_line):
                        advance()
                    else:
                        advance()

                    if not expect(TOKEN_LBRACKET,
                                  f"Role '{role_name}' permissions missing '['",
                                  perm_line):
                        advance()
                    else:
                        advance()

                    found_rbracket = False

                    while current().type not in [TOKEN_EOF]:

                        if current().type == TOKEN_RBRACKET:
                            found_rbracket = True
                            break

                        if current().type in [TOKEN_ROLE, TOKEN_USER]:
                            break

                        if current().type == TOKEN_IDENTIFIER:
                            perm = current().value
                            role_obj.add_permission(perm)
                            node.permissions.append(perm)

                        advance()

                    if found_rbracket:
                        advance()
                    else:
                        add_error(
                            f"[SYNTAX ERROR] Line {perm_line}: "
                            f"Role '{role_name}' missing ']'"
                        )

                else:
                    advance()

            if current().type == TOKEN_RBRACE:
                advance()
            else:
                add_error(
                    f"[SYNTAX ERROR] Line {role_line}: "
                    f"Role '{role_name}' missing '}}'"
                )

            ast_nodes.append(node)
            continue

        elif tok.type == TOKEN_USER:

            user_line = tok.line
            advance()

            if not expect(TOKEN_IDENTIFIER, "Expected user name", user_line):
                advance()
                continue

            user_name = current().value
            advance()

            table.add_user(user_name, user_line)
            user_obj = table.get_user(user_name)
            node = ASTNode("User", user_name)

            if not expect(TOKEN_LBRACE,
                          f"User '{user_name}' missing '{{'",
                          user_line):
                while current().type not in [TOKEN_LBRACE, TOKEN_EOF]:
                    advance()

            if current().type == TOKEN_LBRACE:
                advance()

            while current().type not in [TOKEN_RBRACE, TOKEN_EOF]:

                if current().type in [TOKEN_ROLE, TOKEN_USER]:
                    break

                if current().type == TOKEN_ROLES:

                    roles_line = current().line
                    advance()

                    if not expect(TOKEN_EQUALS,
                                  f"User '{user_name}' roles missing '='",
                                  roles_line):
                        advance()
                    else:
                        advance()

                    if not expect(TOKEN_LBRACKET,
                                  f"User '{user_name}' roles missing '['",
                                  roles_line):
                        advance()
                    else:
                        advance()

                    found_rbracket = False

                    while current().type not in [TOKEN_EOF]:

                        if current().type == TOKEN_RBRACKET:
                            found_rbracket = True
                            break

                        if current().type in [TOKEN_ROLE, TOKEN_USER]:
                            break

                        if current().type == TOKEN_IDENTIFIER:
                            assigned = current().value
                            user_obj.assign_role(assigned)
                            node.roles.append(assigned)

                        advance()

                    if found_rbracket:
                        advance()
                    else:
                        add_error(
                            f"[SYNTAX ERROR] Line {roles_line}: "
                            f"User '{user_name}' missing ']'"
                        )

                else:
                    advance()

            if current().type == TOKEN_RBRACE:
                advance()
            else:
                add_error(
                    f"[SYNTAX ERROR] Line {user_line}: "
                    f"User '{user_name}' missing '}}'"
                )

            ast_nodes.append(node)
            continue
        elif tok.type == TOKEN_MUTEX:

            mutex_line = tok.line
            advance()

            if not expect(TOKEN_IDENTIFIER,
                          "Expected first role name after 'mutex'",
                          mutex_line):
                advance()
                continue

            role1 = current().value
            advance()

            if not expect(TOKEN_IDENTIFIER,
                          "Expected second role name after 'mutex'",
                          mutex_line):
                advance()
                continue

            role2 = current().value
            advance()

            table.mutex_pairs.add((role1, role2))
            continue
        else:
            add_error(
                f"[SYNTAX ERROR] Line {tok.line}: "
                f"Unexpected token '{tok.value}'"
            )
            advance()

    with open("syntax_errors.txt", "w") as f:
        for err in syntax_errors:
            f.write(err + "\n")

    return table, ast_nodes, syntax_errors