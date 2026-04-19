import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import networkx as nx
import os
from datetime import datetime

import hashlib
import json

# --- 1. IMPORT CORE LOGIC ---
from frontend.parser import parse_policy
from core.security_analysis import run_security_analysis
from core.remediation import generate_remediation_proposals
from frontend.semantic import perform_semantic_analysis
from core.ai_agent import call_gemini_to_fix

# --- 2. PAGE CONFIG ---
st.set_page_config(page_title="RBAC Security Auditor", page_icon="🛡️", layout="wide")

# --- 3. UI STYLING ---
st.markdown("""
    <style>
    [data-testid="stMetric"] {
        border: 1px solid #4B5563;
        padding: 15px;
        border-radius: 12px;
        background-color: rgba(128, 128, 128, 0.1);
    }
    .stAlert { border-radius: 10px; }
    </style>
    """, unsafe_allow_html=True)

# --- 4. INITIALIZE SESSION STATE ---
if 'current_code' not in st.session_state:
    st.session_state.current_code = "role Admin { permissions = [all] }"
if 'last_loaded_file' not in st.session_state:
    st.session_state.last_loaded_file = "New_Policy.rbac"

# --- 5. SIDEBAR: FILE EXPLORER ---
st.sidebar.header("🔑 AI Integration")
api_key = st.sidebar.text_input("Gemini API Key", type="password")
if api_key:
    os.environ["GEMINI_API_KEY"] = api_key

st.sidebar.write("---")
st.sidebar.header("📁 RBAC File Explorer")
dsl_folder = "dsl"
if not os.path.exists(dsl_folder):
    os.makedirs(dsl_folder)

files = [f for f in os.listdir(dsl_folder) if f.endswith(".rbac")]

if files:
    selected_file = st.sidebar.selectbox("Select a Policy File:", files)
    if st.sidebar.button("📂 Open & Audit File"):
        with open(os.path.join(dsl_folder, selected_file), "r") as f:
            content = f.read()
            st.session_state.current_code = content
            st.session_state.last_loaded_file = selected_file
        st.rerun()

# --- 6. SIDEBAR: QUICK TEST SUITE ---
st.sidebar.write("---")
st.sidebar.header("🧪 Week 12 Scenarios")
test_cases = {
    "🏥 Medical (Complex)": """# Healthcare Policy
role Doctor { permissions = [prescribe_meds] }
role Pharmacist { permissions = [fill_rx] }
mutex Doctor Pharmacist
user Smith { roles = [Doctor, Pharmacist] }""",
    "✅ Secure Policy": "role User { permissions = [read] }\nuser Alice { roles = [User] }",
    "🔥 Privilege Escalation": "role Admin { permissions = [delete] }\nrole Intern extends Admin { permissions = [read] }\nuser BadActor { roles = [Intern] }",
    "🔄 Circular Trap": "role A extends B { }\nrole B extends A { }"
}

selected_label = st.sidebar.selectbox("Load Scenario:", list(test_cases.keys()))
if st.sidebar.button("🚀 Load Scenario"):
    st.session_state.current_code = test_cases[selected_label]
    st.session_state.last_loaded_file = "Scenario_" + selected_label.split()[1]
    st.rerun()

# --- 7. ANALYSIS PIPELINE ---
def run_pipeline(code):
    with open("temp.rbac", "w") as f: 
        f.write(code)
    table, ast, s_errs = parse_policy("temp.rbac")
    sem_errs = perform_semantic_analysis(table) if table else []
    sec_res = run_security_analysis(table) if table else []
    props = generate_remediation_proposals(table, sec_res) if table else []
    return table, s_errs, sem_errs, sec_res, props

table, s_errs, sem_errs, sec_res, props = run_pipeline(st.session_state.current_code)

# --- NEW: REPORT GENERATOR FUNCTION ---
def get_report_content():
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report = f"RBAC AUDIT & REMEDIATION REPORT\nGenerated: {now}\nFile: {st.session_state.last_loaded_file}\n"
    report += "="*50 + "\n\n"
    
    report += "1. SYNTAX ERRORS:\n" + ("\n".join(s_errs) if s_errs else "None") + "\n\n"
    report += "2. SEMANTIC ERRORS:\n" + ("\n".join(sem_errs) if sem_errs else "None") + "\n\n"
    report += "3. SECURITY RISKS:\n"
    if sec_res:
        for r in sec_res: report += f"- [{r['category']}] {r['msg']} (Evidence: {r['evidence']})\n"
    else: report += "None\n"
    
    report += "\n4. PROPOSED REMEDIATIONS:\n"
    if props:
        for p in props: report += f"- Target: {p['target']} | Action: {p['action']}\n  Reason: {p['reason']}\n"
    else: report += "Policy is already optimized.\n"
    
    return report

# --- 8. DASHBOARD METRICS ---
st.title("🛡️ RBAC Compiler & Security Dashboard")
m_col1, m_col2, m_col3, m_col4 = st.columns(4)

total_roles = len(table.roles) if table else 0
total_users = len(table.users) if table else 0
critical_risks = len(sec_res)
health = max(0, 100 - (critical_risks * 15 + len(s_errs) * 10 + len(sem_errs) * 5))

m_col1.metric("Total Roles", total_roles)
m_col2.metric("Total Users", total_users)
m_col3.metric("Critical Risks", critical_risks, delta=f"-{critical_risks}" if critical_risks > 0 else "Clear", delta_color="inverse")
m_col4.metric("Security Health", f"{health}%")

# --- 9. MAIN TABS ---
tab_edit, tab_audit, tab_viz, tab_fix, tab_ledger = st.tabs([
    "📝 Live Editor", "🔍 Comprehensive Audit", "🕸️ Analytics & Circles", "💡 Remediation", "📜 Contract Ledger"
])

# TAB 1: EDITOR
with tab_edit:
    st.subheader(f"Active File: {st.session_state.last_loaded_file}")
    edited_code = st.text_area("RBAC DSL Editor", height=400, value=st.session_state.current_code)
    
    c1, c2 = st.columns([1, 4])
    if c1.button("🔄 Sync & Re-run"):
        st.session_state.current_code = edited_code
        st.rerun()
    
    if c2.button("💾 Save to File"):
        filename = st.session_state.last_loaded_file
        if not filename.endswith(".rbac"): filename += ".rbac"
        with open(os.path.join(dsl_folder, filename), "w") as f:
            f.write(edited_code)
        st.success(f"Successfully saved to {filename}")

# TAB 2: COMPREHENSIVE AUDIT
with tab_audit:
    st.subheader("Compiler Pipeline Status")
    
    # Download Button for Audit
    st.download_button(
        label="📥 Download Full Audit Report",
        data=get_report_content(),
        file_name=f"audit_{st.session_state.last_loaded_file}.txt",
        mime="text/plain"
    )
    
    st.write("---")
    st.markdown("##### 🛠️ Phase 2: Syntax Analysis")
    if s_errs:
        for e in s_errs: st.error(f"Syntax: {e}")
    else: st.success("✅ No Syntax Errors")

    st.markdown("##### 🧬 Phase 3: Semantic Validation")
    if sem_errs:
        for w in sem_errs: st.warning(f"Semantic: {w}")
    elif table: st.success("✅ Logical Consistency Verified")

    st.markdown("##### 🔥 Phase 4: Security Risks")
    if sec_res:
        for r in sec_res:
            st.error(f"**{r['category']}**: {r['msg']}")
            st.caption(f"Evidence: {r['evidence']}")
    else: st.success("✅ No Security Violations")

# TAB 3: VISUALIZATION
with tab_viz:
    if table:
        v1, v2 = st.columns(2)
        with v1:
            st.subheader("Inheritance Map")
            G = nx.DiGraph()
            for n, r in table.roles.items():
                G.add_node(n)
                for p in r.parents: G.add_edge(p, n) 
            
            if G.nodes:
                try:
                    cycles = list(nx.simple_cycles(G))
                    if cycles:
                        st.error(f"⚠️ Circular Dependency: {' -> '.join(cycles[0])} -> {cycles[0][0]}")
                    else:
                        layers = {}
                        for node in nx.topological_sort(G):
                            parents = list(G.predecessors(node))
                            layers[node] = 0 if not parents else max(layers[p] for p in parents) + 1
                        for node, layer in layers.items(): G.nodes[node]['subset'] = layer
                        pos = nx.multipartite_layout(G, subset_key="subset", align='horizontal')
                        for node in pos: pos[node][1] = -pos[node][1]

                        edge_trace = go.Scatter(x=[], y=[], line=dict(width=1, color='#888'), hoverinfo='none', mode='lines')
                        for edge in G.edges():
                            x0, y0 = pos[edge[0]]; x1, y1 = pos[edge[1]]
                            edge_trace['x'] += (x0, x1, None); edge_trace['y'] += (y0, y1, None)
                        
                        node_trace = go.Scatter(x=[pos[n][0] for n in G.nodes()], y=[pos[n][1] for n in G.nodes()], 
                                                mode='markers+text', text=list(G.nodes()), textposition="bottom center",
                                                marker=dict(size=20, color='#3b82f6', line=dict(width=2, color='white')))

                        fig = go.Figure(data=[edge_trace, node_trace], layout=go.Layout(showlegend=False, xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                                        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False), margin=dict(b=0,l=0,r=0,t=0)))
                        st.plotly_chart(fig, use_container_width=True)
                except: st.warning("Visualizer Error: Fix syntax first.")
        with v2:
            st.subheader("Permission Distribution")
            df = pd.DataFrame([{"Role": k, "Perms": len(v.permissions)} for k,v in table.roles.items()])
            if not df.empty:
                st.plotly_chart(px.pie(df, values='Perms', names='Role', hole=0.5, template="plotly_dark"), use_container_width=True)

# TAB 4: REMEDIATION
# --- 4. UPDATED REMEDIATION TAB ---
with tab_fix:
    st.subheader("💡 Intelligent Remediation Strategy")
    
    # --- PHASE 1 & 2: SYNTAX & SEMANTIC SUGGESTIONS ---
    if s_errs or sem_errs:
        st.error("🛑 **Structural Fixes Required First**")
        st.info("The Security Auditor is currently blocked. Follow these suggestions to unlock full scanning:")
        
        # 1. Syntax Suggestions
        if s_errs:
            with st.expander("🛠️ Syntax Fixes (Grammar)", expanded=True):
                for err in s_errs:
                    st.write(f"**Issue:** {err}")
                    if "{" in err or "}" in err:
                        st.success("💡 **Suggestion:** Check your curly braces. Every `role { ... }` block must be closed.")
                    elif "[" in err or "]" in err:
                        st.success("💡 **Suggestion:** Check your permission lists. Use `[perm1, perm2]` format.")
                    else:
                        st.success("💡 **Suggestion:** Check for missing colons or typos in keywords like 'role' or 'user'.")

        # 2. Semantic Suggestions (Logic)
        if sem_errs:
            with st.expander("🧬 Semantic Fixes (Logic)", expanded=True):
                for err in sem_errs:
                    st.write(f"**Issue:** {err}")
                    if "undefined" in err.lower():
                        st.success("💡 **Suggestion:** This role name doesn't exist. Check for typos or define the role first.")
                    elif "circular" in err.lower() or "cycle" in err.lower():
                        st.warning("💡 **Suggestion:** Break the inheritance loop. A role cannot extend itself or its own children.")
                    elif "mutex" in err.lower():
                        st.success("💡 **Suggestion:** A user is assigned to forbidden roles. Revoke one of the conflicting roles.")
                    elif "no permissions" in err.lower():
                        st.success("💡 **Suggestion:** This is a 'Zombie Role'. Add permissions or remove the role definition.")

    # --- PHASE 4: SECURITY REMEDIATION (Only if structure is OK) ---
    elif props:
        st.success("✅ Structure Verified. Applying Security Heuristics...")
        # Download Button for the Full Fix Plan
        st.download_button(
            label="📥 Download Remediation Plan (.txt)",
            data=get_report_content(), # Uses your existing report function
            file_name=f"fix_plan_{st.session_state.last_loaded_file}.txt",
            mime="text/plain"
        )
        
        for p in props:
            with st.expander(f"Fix for {p['target']} ({p.get('type', 'SECURITY')})", expanded=True):
                st.write(f"**Reason:** {p['reason']}")
                st.info(f"**Action:** {p['action']}")
                
    elif health == 100:
        st.success("✨ **Policy Optimized.** Your RBAC configuration is structurally sound and secure.")

    st.markdown("---")
    st.subheader("🤖 AI Self-Healing")
    all_errors = s_errs + sem_errs + [f"[{r['category']}] {r['msg']}" for r in sec_res]
    if all_errors and health < 100:
        st.warning("Issues detected. You can use AI to automatically fix them.")
        if st.button("🪄 Trigger AI Self-Healing", type="primary"):
            if not os.environ.get("GEMINI_API_KEY"):
                st.error("Please enter your Gemini API Key in the sidebar.")
            else:
                with st.spinner("AI is analyzing and fixing the policy..."):
                    patched_code, err = call_gemini_to_fix(all_errors, st.session_state.current_code)
                    if err:
                        st.error(f"Failed to heal: {err}")
                    else:
                        st.session_state.current_code = patched_code
                        st.success("Policy fixed successfully!")
                        st.rerun()
    elif health == 100:
        st.success("No issues to fix. Policy is 100% healthy.")
        st.markdown("### Current Healthy Policy")
        st.code(st.session_state.current_code, language="text")
        
        if st.button("💾 Save Changes to File", key="save_remediated_policy"):
            filename = st.session_state.last_loaded_file
            if not filename.endswith(".rbac"): filename += ".rbac"
            with open(os.path.join(dsl_folder, filename), "w") as f:
                f.write(st.session_state.current_code)
            st.success(f"Successfully saved to {filename}")

# TAB 5: CONTRACT LEDGER
with tab_ledger:
    st.subheader("📜 Smart Contract Ledger")
    
    ledger_dir = "ledger"
    if not os.path.exists(ledger_dir):
        os.makedirs(ledger_dir)
        
    ledger_file = os.path.join(ledger_dir, "ledger.json")
    if not os.path.exists(ledger_file):
        with open(ledger_file, "w") as f:
            json.dump([], f)
            
    with open(ledger_file, "r") as f:
        ledger_data = json.load(f)

    if health == 100:
        st.success("✅ Policy is 100% healthy and ready for deployment.")
        if st.button("🚀 Deploy to Ledger", type="primary"):
            current_code = st.session_state.current_code
            timestamp = datetime.now().isoformat()
            code_hash = hashlib.sha256(current_code.encode()).hexdigest()
            
            # Save contract file
            # replace colons for windows filename compatibility
            contract_filename = f"{timestamp.replace(':', '-')}_{code_hash[:8]}.rbac"
            contract_path = os.path.join(ledger_dir, contract_filename)
            with open(contract_path, "w") as f:
                f.write(current_code)
                
            # Update ledger.json
            deployment_record = {
                "timestamp": timestamp,
                "hash": code_hash,
                "file": contract_filename,
                "source_file": st.session_state.last_loaded_file
            }
            ledger_data.append(deployment_record)
            with open(ledger_file, "w") as f:
                json.dump(ledger_data, f, indent=4)
                
            st.success(f"Contract deployed successfully! Hash: {code_hash}")
            st.rerun()
    else:
        st.error(f"❌ Cannot deploy. Health score must be 100% (Current: {health}%).")
        st.info("Please go to the Remediation tab to fix the policy before deployment.")
        
    st.markdown("---")
    st.markdown("### Deployment History")
    if ledger_data:
        df_ledger = pd.DataFrame(ledger_data)
        st.dataframe(df_ledger, use_container_width=True)
    else:
        st.info("No contracts deployed yet.")

st.caption("RBAC Project | Week 12: Final Validation Suite")