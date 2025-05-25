# app/rulegen.py
import os
import logging
import hashlib
import re
import math
import yara # Import yara library for compilation check

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Helper function to sanitize names for YARA rule identifiers (used for rule names, not string values)
def sanitize_yara_name(name):
    s = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    return s.strip('_').lower()

# Helper function to escape strings for YARA string literals
def escape_yara_string(s):
    # Ensure input is a string, decode if bytes
    if isinstance(s, bytes):
        try:
            s = s.decode('utf-8', errors='replace') # Try UTF-8, replace unprintable
        except UnicodeDecodeError:
            # Fallback to hex if decoding fails badly, this is a very aggressive fallback
            # and might result in less readable YARA strings but ensures no errors.
            return s.hex()
    else:
        s = str(s)

    escaped_chars = []
    for char in s:
        char_code = ord(char)
        # Printable ASCII excluding " (0x22) and \ (0x5C)
        if 0x20 <= char_code <= 0x7E and char_code not in [0x22, 0x5C]:
            escaped_chars.append(char)
        elif char_code == 0x22: # Double quote
            escaped_chars.append('\\"')
        elif char_code == 0x5C: # Backslash
            escaped_chars.append('\\\\')
        else: # All other non-printable or special characters -> hex encode
            escaped_chars.append(f'\\x{char_code:02x}')
    return "".join(escaped_chars)


def generate_rules(features: dict, original_filename: str) -> list:
    yara_rules_text = [] # Store rule text strings here
    base_filename = os.path.basename(original_filename)
    
    # Generate a unique ID for the rule to prevent naming collisions,
    # especially if multiple samples have the same base filename.
    # Using a hash of the original filename + random bytes for better uniqueness.
    unique_id = hashlib.md5((original_filename + str(os.urandom(16))).encode()).hexdigest()[:10]

    # --- Rule Type 1: File Hash Rule (Exact Match) ---
    file_md5 = features.get("hash")
    if file_md5 and file_md5 != "hash_calculation_error":
        rule_name = f"File_MD5_{sanitize_yara_name(base_filename)}_{unique_id}"
        rule_content = f"""
rule {rule_name}
{{
    meta:
        author = "Your Team"
        date = "{os.getenv('SCAN_DATE', 'N/A')}"
        description = "Detects file by its MD5 hash: {file_md5}"
        filename = "{base_filename}"
        original_filepath = "{original_filename}"
        source = "MCP Rule Generator - Hash"
        severity = "critical"
        category = "ExactMatch"

    strings:
        // No strings needed for hash-based rule directly

    condition:
        hash.md5(0, filesize) == "{file_md5}"
}}
"""
        try:
            yara.compile(source=rule_content) # Attempt to compile rule immediately
            yara_rules_text.append(rule_content)
            logging.info(f"Generated YARA rule '{rule_name}' (MD5) for {original_filename}")
        except yara.Error as e:
            logging.error(f"Skipping rule '{rule_name}' due to compilation error: {e}")


    # Check if it's a PE file to enable PE-specific rules
    is_pe = features.get("is_pe", False)

    # --- Rule Type 2: Suspicious API Imports (PE-specific, Behavioral) ---
    suspicious_imports = [
        "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
        "OpenProcess", "NtAllocateVirtualMemory", "RtlDecompressBuffer",
        "LdrLoadDll", "NtCreateSection", "SetWindowsHookEx",
        "GetProcAddress", "LoadLibrary", "RegSetValueExA", "RegCreateKeyExA",
        "WinExec", "ShellExecuteA", "URLDownloadToFileA", "InternetOpenA"
    ]
    
    if is_pe and features.get("imports"):
        matched_imports = [imp for imp in features["imports"] if imp in suspicious_imports]
        if matched_imports:
            rule_name = f"PE_Suspicious_Imports_{sanitize_yara_name(base_filename)}_{unique_id}"
            
            import_conditions = []
            for imp in matched_imports:
                import_conditions.append(f'pe.imports("{imp}")')
            
            condition = " or ".join(import_conditions)

            rule_content = f"""
rule {rule_name}
{{
    meta:
        author = "Your Team"
        date = "{os.getenv('SCAN_DATE', 'N/A')}"
        description = "Detects suspicious API imports common in malware, like {', '.join(matched_imports[:3])}"
        filename = "{base_filename}"
        original_filepath = "{original_filename}"
        source = "MCP Rule Generator - PE Imports"
        severity = "medium"
        category = "Behavioral"
        
    strings:
        // No string patterns needed, using PE module

    condition:
        uint16(0) == 0x5A4D and // Check for MZ header (basic PE check)
        {condition}
}}
"""
            try:
                yara.compile(source=rule_content)
                yara_rules_text.append(rule_content)
                logging.info(f"Generated YARA rule '{rule_name}' (PE Imports) for {original_filename}")
            except yara.Error as e:
                logging.error(f"Skipping rule '{rule_name}' due to compilation error: {e}")


    # --- Rule Type 3: High Entropy Section (PE-specific, Packing/Obfuscation) ---
    if is_pe and features.get("sections"):
        for i, section in enumerate(features["sections"]):
            if section.get("entropy", 0.0) > 7.5: # Threshold for high entropy
                rule_name = f"PE_HighEntropy_Section_{sanitize_yara_name(section.get('name', 'unknown'))}_{sanitize_yara_name(base_filename)}_{unique_id}"
                
                # IMPORTANT: Escape the section name before embedding it in the YARA rule
                # Section names can contain problematic characters (e.g., non-printable, quotes)
                escaped_section_name = escape_yara_string(section.get('name', ''))

                # Only generate if the escaped section name is not empty
                if escaped_section_name:
                    rule_content = f"""
rule {rule_name}
{{
    meta:
        author = "Your Team"
        date = "{os.getenv('SCAN_DATE', 'N/A')}"
        description = "Detects high entropy in section '{escaped_section_name}' ({section['entropy']:.2f} bits/byte), often indicating packing/encryption."
        filename = "{base_filename}"
        original_filepath = "{original_filename}"
        source = "MCP Rule Generator - High Entropy Section"
        severity = "medium"
        category = "Packing"
    strings:
        // No strings needed, using math module

    condition:
        uint16(0) == 0x5A4D and // Check for MZ header (basic PE check)
        for any i in 0..pe.number_of_sections - 1 : (
            pe.sections[i].name == "{escaped_section_name}" and
            math.entropy(pe.sections[i].offset, pe.sections[i].size) > 7.5
        )
}}
"""
                    try:
                        yara.compile(source=rule_content)
                        yara_rules_text.append(rule_content)
                        logging.info(f"Generated YARA rule '{rule_name}' (High Entropy Section) for {original_filename}")
                    except yara.Error as e:
                        logging.error(f"Skipping rule '{rule_name}' due to compilation error: {e}")


    # --- Rule Type 4: Suspicious Section Names (PE-specific) ---
    suspicious_section_names = [
        "UPX0", "UPX1", "UPX2", ".pyc", ".aspack", ".RLOC", ".themida",
        ".MPRESS1", ".MPRESS2", ".packed", ".exe", ".dll",
    ]
    if is_pe and features.get("sections"):
        matched_section_names = [s['name'] for s in features["sections"] if s['name'] in suspicious_section_names]
        if matched_section_names:
            rule_name = f"PE_Suspicious_Section_Names_{sanitize_yara_name(base_filename)}_{unique_id}"
            
            section_name_conditions = []
            for name in matched_section_names:
                # IMPORTANT: Escape the section name here too
                escaped_name = escape_yara_string(name)
                if escaped_name:
                    section_name_conditions.append(f'for any i in 0..pe.number_of_sections - 1 : (pe.sections[i].name == "{escaped_name}")')
            
            # Only generate rule if there are valid conditions
            if section_name_conditions:
                # Format conditions with line breaks for readability and robustness against long lines
                condition_parts = [
                    "uint16(0) == 0x5A4D and", # Check for MZ header (basic PE check)
                    "( " + " or ".join(section_name_conditions) + " )"
                ]
                rule_content = f"""
rule {rule_name}
{{
    meta:
        author = "Your Team"
        date = "{os.getenv('SCAN_DATE', 'N/A')}"
        description = "Detects suspicious section names like {', '.join(matched_section_names[:3])}, often indicative of packers or custom sections."
        filename = "{base_filename}"
        original_filepath = "{original_filename}"
        source = "MCP Rule Generator - Section Names"
        severity = "low"
        category = "Packing"

    strings:
        // No strings needed, using PE module

    condition:
{os.linesep.join([f'        {part}' for part in condition_parts])}
}}
"""
                try:
                    yara.compile(source=rule_content)
                    yara_rules_text.append(rule_content)
                    logging.info(f"Generated YARA rule '{rule_name}' (Suspicious Section Names) for {original_filename})")
                except yara.Error as e:
                    logging.error(f"Skipping rule '{rule_name}' due to compilation error: {e}")


    # --- Rule Type 5: Generic Suspicious Strings (Fallback/Any File) ---
    generic_suspicious_strings = [
        "http://", "https://", "ftp://", ".exe", ".dll", ".vbs", ".ps1",
        "powershell.exe", "cmd.exe", "rundll32.exe", "explorer.exe",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify",
        # Common malware strings not tied to specific APIs
    ]

    sample_strings = features.get('strings', [])
    matched_generic_strings = []
    # Only add strings from generic_suspicious_strings that are actually found in the sample
    for gen_str in generic_suspicious_strings:
        # Check if the string exists and is a string type
        if isinstance(gen_str, str) and any(gen_str.lower() in s.lower() for s in sample_strings if isinstance(s, str)):
            matched_generic_strings.append(gen_str)

    matched_generic_strings = list(set(matched_generic_strings)) # Remove duplicates
    
    max_strings_per_rule = 50
    if len(matched_generic_strings) > max_strings_per_rule:
        logging.warning(f"Limiting generic strings to {max_strings_per_rule} for {base_filename}")
        matched_generic_strings = matched_generic_strings[:max_strings_per_rule]
    
    if matched_generic_strings:
        strings_section_generic = []
        string_identifiers_generic = []
        for i, matched_string in enumerate(matched_generic_strings):
            identifier = f"$g{i}"
            escaped_string = escape_yara_string(matched_string)
            
            # Only add if the escaped string is not empty, and has a reasonable length
            # A completely empty string or very short string might not be useful, skip if it causes issues.
            if escaped_string and len(escaped_string.strip()) > 0: # Ensures not just spaces
                strings_section_generic.append(f'{identifier} = "{escaped_string}" nocase ascii wide')
                string_identifiers_generic.append(identifier)

        condition_generic = f"any of ({','.join(string_identifiers_generic)})" if string_identifiers_generic else "false"
        
        if condition_generic != "false": # Only generate the rule if it has a valid condition
            rule_name_generic = f"Generic_Suspicious_Strings_{sanitize_yara_name(base_filename)}_{unique_id}"

            # Ensure strings section is not empty, add a comment if no strings were generated
            strings_content = os.linesep.join([f'        {s}' for s in strings_section_generic])
            if not strings_content.strip(): # Check if it's effectively empty (just whitespace)
                strings_content = "        // No suspicious strings found for this rule"

            rule_content = f"""
rule {rule_name_generic}
{{
    meta:
        author = "Your Team"
        date = "{os.getenv('SCAN_DATE', 'N/A')}"
        description = "Detects generic suspicious strings like {', '.join(matched_generic_strings[:3])}"
        filename = "{base_filename}"
        original_filepath = "{original_filename}"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
{strings_content}

    condition:
        {condition_generic}
}}
"""
            try:
                yara.compile(source=rule_content)
                yara_rules_text.append(rule_content)
                logging.info(f"Generated YARA rule '{rule_name_generic}' (Generic Strings) for {original_filename})")
            except yara.Error as e:
                logging.error(f"Skipping rule '{rule_name_generic}' due to compilation error: {e}")


    if features.get("error"):
        error_message = features.get("error", "Unknown analysis error")
        error_type = features.get("type", "generic_error")
        logging.warning(f"Skipping YARA rule generation for {original_filename} due to analysis error: {error_message} ({error_type})")

    logging.info(f"Successfully generated {len(yara_rules_text)} compilable YARA rules for {original_filename}")


    return yara_rules_text
