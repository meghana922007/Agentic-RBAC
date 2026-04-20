import os
import random

def generate_rbac(filename, include_syntax_errors=False):
    lines = []
    lines.append('# Enterprise DeFi Protocol & DAO Access Control Policy')
    lines.append('# Generated for Scalability and Security Auditing')
    lines.append('')
    
    lines.append('role BaseUser { permissions = [read_public_data] }')
    lines.append('role KYCUser extends BaseUser { permissions = [deposit, withdraw] }')
    lines.append('role YieldFarmer extends KYCUser { permissions = [stake, claim_rewards] }')
    lines.append('')
    
    lines.append('role TreasuryManager { permissions = [approve_cheque, transfer_funds] }')
    lines.append('role ProtocolDeployer { permissions = [deploy_code, upgrade_contracts] }')
    lines.append('role ProtocolAuditor { permissions = [audit_code, view_private_logs] }')
    lines.append('role Developer { permissions = [commit_code, write_cheque] }')
    lines.append('')
    
    if include_syntax_errors:
        lines.append('role MaliciousFarmer extends YieldFarmer, TreasuryManager { permissions = [flash_loan] ')
    else:
        lines.append('role MaliciousFarmer extends YieldFarmer, TreasuryManager { permissions = [flash_loan] }')
    
    lines.append('mutex ProtocolAuditor ProtocolDeployer')
    lines.append('mutex TreasuryManager Developer')
    lines.append('')
    
    for i in range(1, 11):
        lines.append(f'role V{i}_Migrator {{ permissions = [migrate_v{i}_state] }}')
    lines.append('')
    
    for i in range(1, 6):
        lines.append(f'user DormantWallet_{i} {{ roles = [] }}')
        
    lines.append('user DeFi_Whale { roles = [KYCUser, YieldFarmer, TreasuryManager, ProtocolAuditor, Developer] }')
    lines.append('user RogueAuditor { roles = [ProtocolAuditor, ProtocolDeployer] }')
    lines.append('user ToxicDev { roles = [Developer, ProtocolDeployer] }')
    
    for i in range(1, 450):
        roles = random.sample(['BaseUser', 'KYCUser', 'YieldFarmer'], random.randint(1, 2))
        roles_str = ", ".join(roles)
        if include_syntax_errors and i == 50:
            lines.append(f'user Degen_{i} {{ roles = [{roles_str}] ')
        elif include_syntax_errors and i == 75:
            lines.append(f'user Degen_{i} {{ roles  [{roles_str}] }}')
        else:
            lines.append(f'user Degen_{i} {{ roles = [{roles_str}] }}')

    with open(filename, 'w') as f:
        f.write(chr(10).join(lines))

if not os.path.exists('dsl'):
    os.makedirs('dsl')

generate_rbac('dsl/Enterprise_DeFi_Perfect_Syntax.rbac', include_syntax_errors=False)
generate_rbac('dsl/Enterprise_DeFi_Broken_Syntax.rbac', include_syntax_errors=True)
print('Generated successfully')
