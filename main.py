from frontend.lexer import lex
from frontend.parser import parse_policy
from frontend.semantic import perform_semantic_analysis
from core.security_analysis import run_security_analysis

DSL_FILE = "dsl/policy.rbac"

PRINT_TOKENS = False
PRINT_AST = True

print("\n" + "="*50)
print("   RBAC POLICY DSL COMPILER - WEEK 10 (EXPLAINABLE)")
print("="*50)

# --- Phase 1: Lexical ---
print("\n[Phase 1] Lexical Analysis...")
tokens = lex(DSL_FILE)

# --- Phase 2: Parsing ---
print("[Phase 2] Parsing & Symbol Table Construction...")
table, ast_nodes, syntax_errors = parse_policy(DSL_FILE)

if syntax_errors:
    print("❌ Syntax Errors Found!")
    for err in syntax_errors: print(err)
else:
    print(f"✅ Success: {len(table.roles)} Roles, {len(table.users)} Users loaded.")

# --- Phase 3: Semantic ---
print("\n[Phase 3] Semantic Analysis...")
semantic_errors = perform_semantic_analysis(table)

if semantic_errors:
    print("❌ Semantic Issues Found:")
    for err in semantic_errors: print(err)
else:
    print("✅ No semantic issues detected.")

# --- Phase 4: Explainable Security Audit (Week 10) ---
print("\n[Phase 4] Explainable Security Audit & Risk Assessment")
print("-" * 60)

security_results = run_security_analysis(table)

if security_results:
    critical_count = 0
    
    with open("security_audit_report.txt", "w") as f:
        f.write("WEEK 10 SECURITY AUDIT REPORT\n")
        f.write("="*35 + "\n\n")

        for issue in security_results:
            # Handle structured dictionary results from Week 10
            if isinstance(issue, dict):
                level = issue.get('level', 'INFO')
                msg = issue.get('msg', '')
                evidence = issue.get('evidence', '')
                
                if level == "CRITICAL":
                    icon = "🔥"
                    critical_count += 1
                elif level == "WARNING":
                    icon = "⚠️ "
                else:
                    icon = "ℹ️ "

                print(f"{icon} {level}: {msg}")
                print(f"   ↳ REASON: {evidence}\n")
                
                # Write to file
                f.write(f"[{level}] {msg}\n")
                f.write(f"REASON: {evidence}\n\n")
            
            # Fallback for old string-based results
            else:
                print(f"ℹ️  INFO: {issue}")
                f.write(f"INFO: {issue}\n\n")

    print("-" * 60)
    print(f"Summary: Found {critical_count} Critical Escalations.")
    print("Detailed evidence saved to 'security_audit_report.txt'")
else:
    print("✅ PASS: No security violations detected.")
from core.remediation import generate_remediation_proposals, verify_improvements

# --- Phase 5: Remediation & Verification (Week 11) ---
print("\n[Phase 5] Agent-Assisted Remediation & Verification")
print("=" * 60)

# 1. Generate suggestions
proposals = generate_remediation_proposals(table, security_results)

if proposals:
    print(f"Proposed {len(proposals)} fixes to optimize the policy.")
    
    # 2. Verify: Run the "What-If" analysis
    old_issue_count = len(security_results)
    new_issue_count, remaining_issues = verify_improvements(table, proposals)
    
    print(f"Verification Results:")
    print(f" 📉 Initial Security Issues: {old_issue_count}")
    print(f" 📉 Post-Remediation Issues: {new_issue_count}")
    
    if new_issue_count < old_issue_count:
        print(" ✅ VERIFIED: Suggested changes will resolve security vulnerabilities.")
    
    # 3. Generate Deliverable: Before-and-After Comparison Report
    with open("remediation_comparison_report.txt", "w") as f:
        f.write("RBAC POLICY: BEFORE-AND-AFTER COMPARISON\n")
        f.write("="*40 + "\n\n")
        f.write(f"STATUS: {'IMPROVED' if new_issue_count < old_issue_count else 'NO CHANGE'}\n")
        f.write(f"CRITICAL ISSUES (BEFORE): {old_issue_count}\n")
        f.write(f"CRITICAL ISSUES (AFTER):  {new_issue_count}\n\n")
        
        f.write("APPLIED REMEDIATIONS:\n")
        for i, p in enumerate(proposals, 1):
            f.write(f"{i}. {p['action']}\n")
            f.write(f"   Reason: {p['reason']}\n")
            
        if remaining_issues:
            f.write("\nREMAINING CONCERNS:\n")
            for ri in remaining_issues:
                f.write(f"- {ri['msg']}\n")
        else:
            f.write("\nSUCCESS: Policy is now clean and optimized.\n")

    print("\nComparison report generated: 'remediation_comparison_report.txt'")
else:
    print("✅ Verified: Policy is already at peak security.")
print("\nCompilation Finished.")