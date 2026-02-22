from frontend.lexer import lex
from frontend.parser import parse_policy
from frontend.semantic import perform_semantic_analysis

DSL_FILE = "dsl/policy.rbac"

PRINT_TOKENS = False
PRINT_AST = True

print("\n==============================")
print(" RBAC POLICY DSL COMPILER")
print("==============================\n")

print("[Phase 1] Lexical Analysis")

tokens = lex(DSL_FILE)
print(f"Tokens generated: {len(tokens) - 1} (excluding EOF)\n")

if PRINT_TOKENS:
    print("----- TOKENS -----")
    for t in tokens[:-1]:
        print(f"Line {t.line:<3} | {t.type:<15} | {t.value}")
    print()

print("[Phase 2] Parsing & Symbol Table Construction")

table, ast_nodes, syntax_errors = parse_policy(DSL_FILE)

print(f"Roles Loaded: {len(table.roles)}")
print(f"Users Loaded: {len(table.users)}\n")

print("----- SYMBOL TABLE -----")

print("\n[Roles]")
for role in table.roles.values():
    print(f"Role: {role.name}")
    print(f"  Permissions: {', '.join(role.permissions) if role.permissions else 'None'}")
    print(f"  Inherits: {', '.join(role.parents) if role.parents else 'None'}")

print("\n[Users]")
for user in table.users.values():
    print(f"User: {user.name}")
    print(f"  Assigned Roles: {', '.join(user.roles) if user.roles else 'None'}")

def print_ast(node, indent="", is_last=True):
    branch = "└── " if is_last else "├── "
    print(indent + branch + f"{node.type}: {node.name}")

    child_indent = indent + ("    " if is_last else "│   ")

    if node.type == "Role":
        if node.permissions:
            print(child_indent + f"├── Permissions: {', '.join(node.permissions)}")
        if node.parents:
            print(child_indent + f"├── Inherits: {', '.join(node.parents)}")

    if node.type == "User":
        if node.roles:
            print(child_indent + f"├── Roles: {', '.join(node.roles)}")

    children = getattr(node, "children", [])
    for i, child in enumerate(children):
        print_ast(child, child_indent, i == len(children) - 1)


if PRINT_AST:
    print("\n----- AST TREE -----")
    for i, node in enumerate(ast_nodes):
        print_ast(node, "", i == len(ast_nodes) - 1)

if syntax_errors:
    print("\n----- SYNTAX ERRORS -----")
    for err in syntax_errors:
        print(err)

    with open("syntax_errors.txt", "w") as f:
        for err in syntax_errors:
            f.write(err + "\n")

    print("\nSyntax errors written to syntax_errors.txt")

else:
    print("\nNo syntax errors detected.")
    open("syntax_errors.txt", "w").close()

print("\n[Phase 3] Semantic Analysis")

semantic_errors = perform_semantic_analysis(table)

if semantic_errors:
    print("\n----- SEMANTIC ERRORS -----")
    for err in semantic_errors:
        print(err)

else:
    print("No semantic issues detected.")

print(" Compilation Finished")
