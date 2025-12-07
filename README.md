<p align="center">
  <img src="static/logo.png" alt="BurpMCPwn Logo" width="500"/>
</p>

# BurpMCPwn

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Extension-orange.svg)](https://portswigger.net/burp)
[![Python](https://img.shields.io/badge/Python-2.7%20(Jython)-yellow.svg)](https://www.jython.org/)

**BurpMCPwn** is a fully integrated **Burp Suite** extension designed for auditing, interacting with, and securing **Model Context Protocol (MCP)** servers.

> **New in v2**: Native Chat integration! You no longer need to run external scripts. Chat with Claude directly inside Burp to perform agentic security testing.

## 🚀 Features

### 1. Tools & Interaction
- **Connect** to any MCP server via HTTP or SSE.
- **Browse** available tools with auto-generated, pretty HTML documentation.
- **Execute** tools directly from the UI with real-time feedback.
- **Send to Repeater**: One-click generation of valid JSON-RPC requests for manual fuzzing and advanced testing.

### 2. Deep Audit
- **Static Analysis**: Automatically identifies risky function names (e.g., `exec`, `shell`, `sql`) and detects potential poison prompts in tool descriptions.
- **Dynamic Probing**: Fuzzes tools with invalid data types to uncover verbose error leaks or improper validation handling.
- **Reporting**: Generates a prioritized, easy-to-read HTML report of findings.

### 3. Native Agent Chat
- **Anthropic Integration**: Chat directly with **Claude 3.5 Sonnet** using your API key.
- **Autonomous Loop**: The agent can autonomously call MCP tools, interpret results, and iterate to solve complex challenges.
- **CTF Ready**: Perfect for "Give me a flag" style challenges or exploring complex APIs without manual intervention.

## 📦 Installation

### Prerequisites
- **Burp Suite** (Professional or Community Edition).
- **Jython Standalone JAR** (Tested with 2.7.3). [Download here](https://www.jython.org/download).

### Setup
1. Open Burp Suite.
2. Navigate to **Extensions** > **Extensions Settings** > **Python Environment**.
3. Click **Select file** and choose your `jython-standalone.jar`.
4. Go to **Extensions** > **Installed**.
5. Click **Add**.
6. Set **Extension Type** to **Python**.
7. Select the `BurpMCPwn.py` file.

## 🛠 Usage

### 1. Connection
- Enter the **MCP Host URL** (e.g., `http://localhost:8000/mcp`).
- (Optional) Provide a **Token** if the server requires authentication.
- Click **Connect**.

### 2. Manual Testing
- Navigate to the **Tools** tab.
- Select a tool from the list.
- Use the built-in JSON editor to modify arguments.
- Click **Send to Repeater** to inspect and manipulate the raw request.

### 3. Automated Audit
- Navigate to the **Deep Audit** tab.
- Click **Run Deep Audit**.
- Review the generated HTML report for potential vulnerabilities.

### 4. Agent Chat
- Navigate to the **Agent Chat** tab.
- Enter your **Anthropic API Key** (starts with `sk-ant...`) in the configuration bar.
- Input a goal (e.g., *"Explore the file system and find the flag"*).
- Observe the agent as it calls tools and executes tasks.

## ⚠️ Disclaimer

This tool is intended for **legal security auditing and educational purposes only**. usage of BurpMCPwn for attacking targets without prior mutual consent is illegal. The developers assume no liability and are not responsible for any misuse or damage caused by this program.

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
