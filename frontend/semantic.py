def perform_semantic_analysis(table):
    errors = []

    for role_name, line in table.duplicate_roles:
        errors.append(
            f"[SEMANTIC ERROR] Line {line}: Duplicate role '{role_name}'"
        )

    for user_name, line in table.duplicate_users:
        errors.append(
            f"[SEMANTIC ERROR] Line {line}: Duplicate user '{user_name}'"
        )

    for role_name, role_obj in table.roles.items():
        for parent in role_obj.parents:
            if parent not in table.roles:
                errors.append(
                    f"[SEMANTIC ERROR] Line {role_obj.line}: "
                    f"Role '{role_name}' extends undefined role '{parent}'"
                )

    for user_name, user_obj in table.users.items():
        for role in user_obj.roles:
            if role not in table.roles:
                errors.append(
                    f"[SEMANTIC ERROR] Line {user_obj.line}: "
                    f"User '{user_name}' references undefined role '{role}'"
                )
        # Week 8: Mutex Role Conflict Detection
    for user_name, user_obj in table.users.items():
        assigned = set(user_obj.roles)

        for role1, role2 in getattr(table, "mutex_pairs", set()):
            if role1 in assigned and role2 in assigned:
                errors.append(
                    f"[SEMANTIC ERROR] Line {user_obj.line}: "
                    f"User '{user_name}' has mutually exclusive roles "
                    f"'{role1}' and '{role2}'"
                )
    for role_name, role_obj in table.roles.items():
        if not role_obj.permissions and not role_obj.parents:
            errors.append(
                f"[SEMANTIC ERROR] Line {role_obj.line}: "
                f"Role '{role_name}' has no permissions defined"
            )
        # Week 8: Redundant Permission Detection via Inheritance
    for role_name, role_obj in table.roles.items():

        inherited_perms = set()

        for parent in role_obj.parents:
            if parent in table.roles:
                inherited_perms.update(
                    table.roles[parent].permissions
                )

        for perm in role_obj.permissions:
            if perm in inherited_perms:
                errors.append(
                    f"[SEMANTIC WARNING] Line {role_obj.line}: "
                    f"Role '{role_name}' redundantly defines "
                    f"inherited permission '{perm}'"
                )
    visited = set()
    stack = set()

    def dfs(role_name):
        if role_name in stack:
            errors.append(
                f"[SEMANTIC ERROR] Circular inheritance detected involving role '{role_name}'"
            )
            return

        if role_name in visited:
            return

        visited.add(role_name)
        stack.add(role_name)

        role_obj = table.roles.get(role_name)
        if role_obj:
            for parent in role_obj.parents:
                dfs(parent)

        stack.remove(role_name)

    for role_name in table.roles:
        dfs(role_name)

    return errors