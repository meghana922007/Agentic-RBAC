# Agentic-RBAC 🤖🛡️

**An AI-Assisted, Blockchain-Ready Domain Specific Language (DSL) Compiler for Role-Based Access Control (RBAC).**

Agentic-RBAC is an advanced compiler designed to parse, validate, and secure RBAC policies. Moving beyond traditional compiler design, Agentic-RBAC integrates modern paradigms including AI-driven autonomous auto-remediation, Solidity smart contract generation, and Green Computing energy profiling.

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=Streamlit&logoColor=white)
![Solidity](https://img.shields.io/badge/Solidity-363636?style=for-the-badge&logo=solidity&logoColor=white)
![Gemini AI](https://img.shields.io/badge/Gemini_AI-8E75B2?style=for-the-badge&logo=googlebard&logoColor=white)

## ✨ Modern Features

* **Intelligent Compiler Pipeline:** Full lexical, syntax, and semantic analysis to catch structural errors and logical flaws (like circular inheritance and zombie roles).
* **Explainable Security Audit:** Automatically detects privilege escalation paths, conflicting mutex assignments, and potential security loopholes with detailed evidence.
* **🪄 Autonomous AI Self-Healing (Gemini):** Integrates Google Gemini AI to act as an autonomous security agent. It analyzes security risks and proposes—or directly patches—the DSL code to self-heal and optimize the policy.
* **⛓️ Blockchain Readiness:** Automatically translates valid RBAC policies into deployable **Solidity Smart Contracts** and simulates decentralized deployment via an IPFS Ledger.
* **🌱 Green Computing Profiler:** Built-in energy and performance profiler that runs stress tests to calculate CO2 emissions and power consumption (RAM/CPU) of the compiler logic.
* **📊 Interactive Dashboard:** A beautiful, real-time UI built with Streamlit featuring live editing, visual inheritance graphs (NetworkX), and dynamic access simulation.

## 🏗️ Architecture Pipeline

1. **Phase 1 & 2:** Lexical & Syntax Analysis -> *Abstract Syntax Tree (AST)*
2. **Phase 3:** Semantic Validation -> *Logical Consistency*
3. **Phase 4:** Security Heuristics -> *Risk Detection*
4. **Phase 5:** Agentic AI Remediation -> *Self-Healing Code*
5. **Phase 6:** Blockchain Generation -> *Solidity Output*

## 🚀 Getting Started

### Prerequisites
* Python 3.9+
* Google Gemini API Key (For the AI Agent)

### Installation
1. Clone the repository:
   \`\`\`bash
   git clone https://github.com/meghana922007/Agentic-RBAC.git
   cd Agentic-RBAC
   \`\`\`

2. Install dependencies:
   \`\`\`bash
   pip install streamlit pandas plotly networkx
   \`\`\`

### Running the Dashboard
To launch the interactive Streamlit dashboard:
\`\`\`bash
streamlit run app.py
\`\`\`

### Running the CLI Compiler
To run the standard command-line compilation pipeline:
\`\`\`bash
python main.py
\`\`\`

## 🧪 Testing Scenarios
The dashboard comes pre-loaded with several complex test scenarios, including:
- **Healthcare Policy:** Tests complex multi-role assignments and Mutex (Mutually Exclusive) rules.
- **Privilege Escalation:** Demonstrates how the security agent catches bad actors gaining Admin rights through obscure inheritance paths.
- **Circular Trap:** Validates the semantic engine's ability to prevent infinite loops in role extension.

## 📜 Output Artifacts
Depending on your pipeline, Agentic-RBAC generates several artifacts:
* `security_audit_report.txt`: Detailed explanation of security vulnerabilities.
* `remediation_comparison_report.txt`: Before-and-after analysis of the agent's autonomous fixes.
* `ledger/ledger.json`: Simulated IPFS deployment history.

## 🤝 Contributing
Contributions are welcome! If you're interested in adding new security heuristics, improving the AI agent prompts, or optimizing the Solidity generation, please open a PR.
