from core.symbol_table import SymbolTable

def evaluate_access(table: SymbolTable, user_name: str, target_permission: str):
    """
    Evaluates if a user has a specific permission by recursively checking
    all their roles and inherited roles.
    Returns (bool, str) -> (has_access, reasoning)
    """
    user = table.get_user(user_name)
    if not user:
        return False, f"User '{user_name}' does not exist."
        
    roles_to_check = list(user.roles)
    checked_roles = set()
    found_permissions = set()
    
    # BFS to collect all roles and parents
    while roles_to_check:
        current_role_name = roles_to_check.pop(0)
        if current_role_name in checked_roles:
            continue
            
        checked_roles.add(current_role_name)
        role_obj = table.get_role(current_role_name)
        
        if role_obj:
            for p in role_obj.permissions:
                found_permissions.add(p)
            for parent in role_obj.parents:
                if parent not in checked_roles:
                    roles_to_check.append(parent)
                    
    if target_permission in found_permissions:
        return True, f"Access Granted.\nUser '{user_name}' has permission '{target_permission}' via roles: {list(checked_roles)}."
    else:
        return False, f"Access Denied.\nUser '{user_name}' lacks permission '{target_permission}'.\nRoles evaluated: {list(checked_roles)}"
