import os
import random

def generate_medium_rbac():
    lines = []
    lines.append('# Enterprise DeFi Protocol & DAO Access Control Policy (Medium Scale)')
    lines.append('# Designed to be large but 100% AI Healable')
    lines.append('')
    
    # 1. Base Roles
    lines.append('role BaseUser { permissions = [read_public_data] }')
    lines.append('role KYCUser extends BaseUser { permissions = [deposit, withdraw] }')
    lines.append('role YieldFarmer extends KYCUser { permissions = [stake, claim_rewards] }')
    lines.append('')
    
    # 2. Protocol Admin Roles
    lines.append('role TreasuryManager { permissions = [approve_cheque, transfer_funds] }')
    lines.append('role ProtocolDeployer { permissions = [deploy_code, upgrade_contracts] }')
    lines.append('role ProtocolAuditor { permissions = [audit_code, view_private_logs] }')
    lines.append('role Developer { permissions = [commit_code, write_cheque] }')
    lines.append('')
    
    # 3. Security Vulnerabilities
    # Syntax Error (missing brace and equal sign)
    lines.append('role BrokenSyntax extends KYCUser permissions = [stake] ')
    lines.append('')
    
    # Privilege Escalation: YieldFarmer maliciously inherits TreasuryManager
    lines.append('role MaliciousFarmer extends YieldFarmer, TreasuryManager { permissions = [flash_loan] }')
    
    # Mutex
    lines.append('mutex ProtocolAuditor ProtocolDeployer')
    lines.append('mutex TreasuryManager Developer')
    lines.append('')
    
    # Orphaned Roles
    for i in range(1, 4):
        lines.append(f'role V{i}_Migrator {{ permissions = [migrate_v{i}_state] }}')
    lines.append('')
    
    # 4. Generate Users
    # Zombie Users
    for i in range(1, 4):
        lines.append(f'user DormantWallet_{i} {{ roles = [] }}')
        
    # Over-Privileged User (Whale)
    lines.append('user DeFi_Whale { roles = [KYCUser, YieldFarmer, TreasuryManager, ProtocolAuditor, Developer] }')
    
    # Mutex Violation User
    lines.append('user RogueAuditor { roles = [ProtocolAuditor, ProtocolDeployer] }')
    
    # Toxic Combination User (Gets commit_code from Developer, deploy_code from ProtocolDeployer)
    lines.append('user ToxicDev { roles = [Developer, ProtocolDeployer] }')
    lines.append('')
    
    # Normal Users (Fill up to ~120 lines total)
    for i in range(1, 80):
        roles = random.sample(['BaseUser', 'KYCUser', 'YieldFarmer'], random.randint(1, 2))
        roles_str = ", ".join(roles)
        lines.append(f'user Degen_{i} {{ roles = [{roles_str}] }}')

    with open('dsl/Enterprise_Demo_Medium.rbac', 'w') as f:
        f.write(chr(10).join(lines))

if not os.path.exists('dsl'):
    os.makedirs('dsl')

generate_medium_rbac()
print('Generated successfully')
