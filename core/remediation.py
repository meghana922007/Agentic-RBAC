"""
Remediation Engine - Week 11
Focus: Automated Policy Fixes & Restructuring Suggestions
"""
import copy
from core.security_analysis import run_security_analysis

def verify_improvements(table, proposals):
    """
    Week 11: Simulates applying the proposals to a copy of the table 
    and re-runs the security analysis to verify the fix.
    """
    # Create a deep copy so we don't break the actual Symbol Table
    shadow_table = copy.deepcopy(table)
    
    for prop in proposals:
        target = prop['target']
        action = prop['action']
        
        if prop['type'] == "RESTRUCTURE":
            # Action string: "Remove 'extends Manager' from role 'Auditor'"
            parent_to_remove = action.split("'")[1].split(" ")[1]
            if target in shadow_table.roles:
                if parent_to_remove in shadow_table.roles[target].parents:
                    shadow_table.roles[target].parents.remove(parent_to_remove)
                    
        elif prop['type'] == "MINIMIZE":
            # Action string: "Remove explicit permission 'read' from role 'Tester'"
            perm_to_remove = action.split("'")[1]
            if target in shadow_table.roles:
                if perm_to_remove in shadow_table.roles[target].permissions:
                    shadow_table.roles[target].permissions.remove(perm_to_remove)

    # Re-analyze the modified policy
    new_results = run_security_analysis(shadow_table)
    return len(new_results), new_results
def generate_remediation_proposals(table, security_results):
    """
    Analyzes security findings and suggests DSL-level changes.
    """
    proposals = []

    for issue in security_results:
        if not isinstance(issue, dict): continue
        
        category = issue.get('category')
        evidence = issue.get('evidence', '')

        # 1. Fixing Privilege Escalation (Role Restructuring)
        if category == "Privilege Escalation":
            # Extract path from evidence: "Trace: Intern -> Auditor -> Manager -> Admin -> [delete]"
            if "Trace:" in evidence:
                path_part = evidence.split("Trace: ")[1].split(" -> [")[0]
                roles = path_part.split(" -> ")
                
                # Suggest breaking the inheritance at the highest dangerous level
                # If Intern -> Auditor -> Manager, we suggest removing 'extends Manager' from Auditor
                if len(roles) >= 3:
                    target_role = roles[1]
                    parent_to_remove = roles[2]
                    proposals.append({
                        "type": "RESTRUCTURE",
                        "target": target_role,
                        "action": f"Remove 'extends {parent_to_remove}' from role '{target_role}'",
                        "reason": f"Breaks the indirect path allowing '{roles[0]}' to reach sensitive perms."
                    })

        # 2. Fixing Redundancy (Permission Minimization)
        elif category == "Redundancy":
            # Evidence: "Permission 'read' is already provided via inheritance."
            role_name = issue.get('msg').split("'")[1]
            perm_name = issue.get('msg').split("'")[3]
            proposals.append({
                "type": "MINIMIZE",
                "target": role_name,
                "action": f"Remove explicit permission '{perm_name}' from role '{role_name}'",
                "reason": "Permission is already inherited; keeping it makes the policy harder to maintain."
            })

    return proposals