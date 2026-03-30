import streamlit as st
import pandas as pd
import plotly.express as px
import networkx as nx
import os

# Import your core logic
from frontend.parser import parse_policy
from core.security_analysis import run_security_analysis
from core.remediation import generate_remediation_proposals, verify_improvements

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="RBAC Security Auditor",
    page_icon="🛡️",
    layout="wide"
)

# --- CUSTOM CSS FOR "CLEAN & NEAT" LOOK ---
st.markdown("""
    <style>
    .main { background-color: #f5f7f9; }
    .stMetric { background-color: #ffffff; padding: 15px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
    .stAlert { border-radius: 10px; }
    </style>
    """, unsafe_allow_html=True)

st.title("🛡️ RBAC Policy Compiler & Security Dashboard")
st.markdown("##### *Formal Language Analysis & Automated Security Auditing*")
st.write("---")

# --- SIDEBAR ---
st.sidebar.header("📁 Policy Input")
dsl_path = st.sidebar.text_input("RBAC File Path", "dsl/policy.rbac")

if not os.path.exists(dsl_path):
    st.sidebar.error(f"File not found: {dsl_path}")
    st.stop()

# --- RUN ANALYSIS ---
# We run this at the top level so data is available for all tabs
table, ast_nodes, syntax_errors = parse_policy(dsl_path)

if syntax_errors:
    st.error("### ❌ Syntax Errors Detected")
    for err in syntax_errors:
        st.write(f"- {err}")
    st.stop()

# Perform Security Analysis
security_results = run_security_analysis(table)
proposals = generate_remediation_proposals(table, security_results)

# --- METRIC OVERVIEW ---
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Roles", len(table.roles))
col2.metric("Total Users", len(table.users))

critical_count = sum(1 for r in security_results if r['level'] == "CRITICAL")
col3.metric("Critical Risks", critical_count, delta=f"-{critical_count}" if critical_count > 0 else "Clear", delta_color="inverse")

# Calculate "Security Health"
health_score = max(0, 100 - (critical_count * 20))
col4.metric("Security Health", f"{health_score}%")

st.write("")

# --- MAIN TABS ---
tab1, tab2, tab3, tab4 = st.tabs([
    "🔍 Security Audit", 
    "🕸️ Role Hierarchy & Analytics", 
    "💡 Remediation Suggestions",
    "📄 Source Code Viewer"
])

# --- TAB 1: SECURITY AUDIT ---
with tab1:
    st.subheader("Explainable Security Report")
    st.info("Each finding includes a 'Trace' showing the exact inheritance path discovered by the compiler.")
    
    if not security_results:
        st.success("✅ No security violations detected in the current policy.")
    else:
        for issue in security_results:
            level = issue['level']
            icon = "🔥" if level == "CRITICAL" else "⚠️" if level == "WARNING" else "ℹ️"
            
            with st.expander(f"{icon} {level}: {issue['category']} - {issue['msg']}"):
                st.write(f"**Description:** {issue['msg']}")
                st.code(f"Evidence: {issue['evidence']}", language="text")
                if level == "CRITICAL":
                    st.error("Action Required: This path allows unauthorized access to high-privilege permissions.")

# --- TAB 2: VISUALIZATIONS ---
with tab2:
    col_left, col_right = st.columns(2)
    
    with col_left:
        st.subheader("Inheritance Graph")
        # Build the graph
        G = nx.DiGraph()
        for name, role in table.roles.items():
            G.add_node(name)
            for parent in role.parents:
                G.add_edge(parent, name) # Edge from Parent to Child
        
        if not G.edges:
            st.write("No inheritance relationships defined.")
        else:
            # Create a simple coordinate system for nodes
            pos = nx.spring_layout(G)
            edge_x, edge_y = [], []
            for edge in G.edges():
                x0, y0 = pos[edge[0]]
                x1, y1 = pos[edge[1]]
                edge_x.extend([x0, x1, None])
                edge_y.extend([y0, y1, None])

            # Use Plotly for the circle/node graph
            fig_nodes = px.scatter(
                x=[pos[n][0] for n in G.nodes()], 
                y=[pos[n][1] for n in G.nodes()],
                text=list(G.nodes()),
                size=[30]*len(G.nodes()),
                title="Role Inheritance Map"
            )
            fig_nodes.update_traces(textposition='top center', marker=dict(color='#3366CC', line_width=2))
            st.plotly_chart(fig_nodes, use_container_width=True)

    with col_right:
        st.subheader("Permission Distribution")
        # Pie chart (Circles!)
        perm_counts = [{"Role": name, "Permissions": len(role.permissions)} for name, role in table.roles.items()]
        df_perms = pd.DataFrame(perm_counts)
        fig_pie = px.pie(
            df_perms, 
            values='Permissions', 
            names='Role', 
            hole=0.4,
            color_discrete_sequence=px.colors.qualitative.Pastel
        )
        st.plotly_chart(fig_pie, use_container_width=True)

# --- TAB 3: REMEDIATION ---
with tab3:
    st.subheader("Automated Policy Fixes")
    
    if not proposals:
        st.success("No remediation steps needed.")
    else:
        # Before and After Summary
        new_count, _ = verify_improvements(table, proposals)
        
        st.write(f"**Current Issues:** {len(security_results)} | **After Fixes:** {new_count}")
        st.progress(1.0 if new_count == 0 else 0.5)

        for p in proposals:
            st.info(f"**Target Role:** {p['target']}\n\n**Suggested Action:** `{p['action']}`\n\n**Reason:** {p['reason']}")
            
        st.divider()
        st.download_button(
            label="Download Remediation Report",
            data=f"Policy Audit Summary\nBefore: {len(security_results)} issues\nAfter: {new_count} issues\n\nFixes:\n" + "\n".join([f"- {x['action']}" for x in proposals]),
            file_name="security_audit.txt"
        )

# --- TAB 4: SOURCE CODE ---
with tab4:
    st.subheader("Active Policy Content")
    with open(dsl_path, "r") as f:
        code = f.read()
    st.code(code, language="ruby")

st.write("---")
st.caption("RBAC Compiler Project - CS Final Project Deliverable")