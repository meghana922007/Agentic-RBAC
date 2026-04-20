from core.symbol_table import SymbolTable
from datetime import datetime

def generate_solidity_contract(table: SymbolTable, contract_name: str = "RBACPolicy") -> str:
    """
    Generates a Solidity smart contract from the RBAC SymbolTable.
    """
    lines = []
    lines.append("// SPDX-License-Identifier: MIT")
    lines.append(f"// Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("pragma solidity ^0.8.0;")
    lines.append("")
    lines.append('import "@openzeppelin/contracts/access/AccessControl.sol";')
    lines.append("")
    lines.append(f"contract {contract_name} is AccessControl {{")
    
    # 1. Generate Role Hashes
    lines.append("    // --- Roles ---")
    for role_name in table.roles.keys():
        hash_name = f"{role_name.upper()}_ROLE"
        lines.append(f'    bytes32 public constant {hash_name} = keccak256("{hash_name}");')
        
    lines.append("")
    
    # 2. Generate Permissions as basic constants or modifiers
    lines.append("    // --- Permissions (Action Identifiers) ---")
    all_permissions = set()
    for role in table.roles.values():
        for p in role.permissions:
            all_permissions.add(p)
            
    for p in sorted(all_permissions):
        hash_name = f"PERM_{p.upper()}"
        lines.append(f'    bytes32 public constant {hash_name} = keccak256("{hash_name}");')
        
    lines.append("")
    
    # 3. Constructor & Inheritance Setup
    lines.append("    constructor() {")
    lines.append('        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);')
    lines.append("")
    lines.append("        // --- Role Inheritance Setup ---")
    for role_name, role in table.roles.items():
        role_hash = f"{role_name.upper()}_ROLE"
        for parent in role.parents:
            parent_hash = f"{parent.upper()}_ROLE"
            # In OZ AccessControl, _setRoleAdmin sets the admin role that can grant/revoke the child role
            lines.append(f"        _setRoleAdmin({role_hash}, {parent_hash});")
            
    lines.append("    }")
    lines.append("")
    
    # 4. Check Permission Function
    lines.append("    /**")
    lines.append("     * @dev Checks if an account has a specific role.")
    lines.append("     * Note: In a full deployment, you would evaluate permissions here.")
    lines.append("     */")
    lines.append("    function checkRole(bytes32 role, address account) public view returns (bool) {")
    lines.append("        return hasRole(role, account);")
    lines.append("    }")
    lines.append("}")
    
    return "\n".join(lines)
