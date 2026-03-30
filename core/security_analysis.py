"""
Security Analysis Module - Week 10
Focus: Explainable Security Analysis (Root Cause & Traceability)
"""

def get_permission_trace(role_name, table, visited=None, path=None):
    """
    Recursive DFS that tracks the inheritance path for every permission found.
    Returns: A dictionary mapping permission -> [List of roles in the chain]
    Example: {'delete': ['Intern', 'Auditor', 'Manager', 'Admin']}
    """
    if visited is None: visited = set()
    if path is None: path = []
    
    current_path = path + [role_name]
    trace = {}
    
    role_obj = table.get_role(role_name)
    if not role_obj or role_name in visited:
        return trace
    
    visited.add(role_name)
    
    # 1. Map direct permissions to the current path
    for perm in role_obj.permissions:
        trace[perm] = current_path
        
    # 2. Explore parents and merge their traces
    for parent_name in role_obj.parents:
        parent_trace = get_permission_trace(parent_name, table, visited, current_path)
        for perm, p_path in parent_trace.items():
            # Keep the first path found for a permission
            if perm not in trace:
                trace[perm] = p_path
                
    return trace


def detect_privilege_escalation(table):
    """Week 10: Returns CRITICAL findings with inheritance evidence."""
    results = []
    # Permissions that trigger high-security alerts
    SENSITIVE_PERMISSIONS = {"delete", "fire", "manage_payroll", "approve"}
    # Roles allowed to have these permissions
    AUTHORIZED_ROLES = {"Admin", "HR"}

    for role_name in table.roles:
        if role_name in AUTHORIZED_ROLES:
            continue
            
        trace = get_permission_trace(role_name, table)
        
        for perm in SENSITIVE_PERMISSIONS:
            if perm in trace:
                path_str = " -> ".join(trace[perm])
                results.append({
                    "level": "CRITICAL",
                    "category": "Privilege Escalation",
                    "msg": f"Role '{role_name}' has unauthorized access to '{perm}'",
                    "evidence": f"Trace: {path_str} -> [{perm}]"
                })
    return results


def detect_role_conflicts(table):
    """Week 10: Returns WARNING findings for Mutex violations."""
    results = []
    for user_name, user_obj in table.users.items():
        assigned = set(user_obj.roles)
        for role1, role2 in getattr(table, "mutex_pairs", set()):
            if role1 in assigned and role2 in assigned:
                results.append({
                    "level": "WARNING",
                    "category": "Role Conflict",
                    "msg": f"User '{user_name}' violates Separation of Duties (SoD).",
                    "evidence": f"User assigned mutually exclusive roles: '{role1}' and '{role2}'"
                })
    return results


def detect_redundant_permissions(table):
    """Week 10: Returns INFO findings for policy optimization."""
    results = []
    for role_name, role_obj in table.roles.items():
        inherited_perms = set()
        for parent in role_obj.parents:
            inherited_perms.update(get_permission_trace(parent, table).keys())

        for perm in role_obj.permissions:
            if perm in inherited_perms:
                results.append({
                    "level": "INFO",
                    "category": "Redundancy",
                    "msg": f"Role '{role_name}' redefines inherited permission '{perm}'",
                    "evidence": "Clean up suggested: Permission is already provided via inheritance."
                })
    return results


def run_security_analysis(table):
    """
    Main entry point for Week 10.
    Returns a list of structured dictionaries for the reporting engine.
    """
    report = []
    
    # Priority 1: Escalations
    report.extend(detect_privilege_escalation(table))
    
    # Priority 2: Conflicts
    report.extend(detect_role_conflicts(table))
    
    # Priority 3: Redundancy
    report.extend(detect_redundant_permissions(table))
    
    return report