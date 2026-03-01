def detect_role_conflicts(table):
    results = []

    for user_name, user_obj in table.users.items():
        assigned = set(user_obj.roles)

        for role1, role2 in getattr(table, "mutex_pairs", set()):
            if role1 in assigned and role2 in assigned:
                results.append(
                    f"[ROLE CONFLICT] User '{user_name}' "
                    f"has mutually exclusive roles "
                    f"'{role1}' and '{role2}'"
                )

    return results


def detect_redundant_permissions(table):
    results = []

    for role_name, role_obj in table.roles.items():

        inherited_perms = set()

        for parent in role_obj.parents:
            if parent in table.roles:
                inherited_perms.update(
                    table.roles[parent].permissions
                )

        for perm in role_obj.permissions:
            if perm in inherited_perms:
                results.append(
                    f"[REDUNDANCY] Role '{role_name}' "
                    f"redefines inherited permission '{perm}'"
                )

    return results


def enforce_least_privilege(table):
    results = []

    # Empty roles
    for role_name, role_obj in table.roles.items():
        if not role_obj.permissions and not role_obj.parents:
            results.append(
                f"[LEAST PRIVILEGE] Role '{role_name}' "
                f"has no effective permissions"
            )

    # Users assigned undefined roles
    for user_name, user_obj in table.users.items():
        for role in user_obj.roles:
            if role not in table.roles:
                results.append(
                    f"[LEAST PRIVILEGE] User '{user_name}' "
                    f"assigned undefined role '{role}'"
                )

    return results


def run_security_analysis(table):
    report = []

    report.extend(detect_role_conflicts(table))
    report.extend(detect_redundant_permissions(table))
    report.extend(enforce_least_privilege(table))

    return report