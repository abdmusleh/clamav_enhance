# app/analyzer.py
import lief
import hashlib
import os
import logging
import re
import math

# Setup basic logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def analyze_sample(filepath):
    """
    Analyzes a file using LIEF to extract binary features.
    Returns a dictionary of features or an error dictionary if parsing fails.
    """
    binary = None

    try:
        # Attempt to parse the file with LIEF
        binary = lief.parse(filepath)
    except lief.bad_file as e:
        logging.error(f"LIEF parsing error for {filepath}: {e}")
        return {"error": f"LIEF parsing error: {e}", "filepath": filepath, "type": "lief_error"}
    except Exception as e:
        logging.error(f"Unexpected error during LIEF parsing for {filepath}: {e}")
        return {"error": f"Unexpected parsing error: {e}", "filepath": filepath, "type": "generic_error"}

    # If LIEF returns None (unrecognized format but no crash)
    if binary is None:
        logging.warning(f"Unrecognized or unparseable format: {filepath}")
        return {"error": "Unknown executable format or unparseable by LIEF", "filepath": filepath, "type": "unrecognized_format"}

    # Determine if it's a PE (Windows Executable) for PE-specific features
    is_pe = (binary.format == lief.Binary.FORMATS.PE)

    # Extract file features
    strings = extract_strings(filepath)
    hash_val = file_hash(filepath)

    sections_info = []
    total_entropy = 0.0

    # Process sections if they exist
    if binary.sections:
        for s in binary.sections:
            section_entropy = 0.0
            section_offset = 0 # Default to 0 if not found

            try:
                section_entropy = s.entropy
            except AttributeError:
                logging.warning(f"Section '{s.name}' in {filepath} has no entropy attribute.")
            
            # FIX: Safely get pointer_to_raw_data, as it might not exist for all section types (e.g., non-PE)
            try:
                section_offset = s.pointer_to_raw_data
            except AttributeError:
                logging.warning(f"Section '{s.name}' in {filepath} has no pointer_to_raw_data attribute. Defaulting offset to 0.")

            sections_info.append({
                "name": s.name,
                "entropy": section_entropy,
                "virtual_address": s.virtual_address,
                "size": s.size,
                "offset": section_offset
            })
    else:
        logging.info(f"No sections found in: {filepath}")

    # Calculate overall file entropy from raw content
    try:
        with open(filepath, "rb") as f:
            content = f.read()
            total_entropy = calculate_raw_entropy(content)
    except Exception as e:
        logging.warning(f"Failed to calculate total file entropy for {filepath}: {e}")
        total_entropy = 0.0

    # Get imports if it's a PE binary and imports exist
    imports = []
    # FIX: Ensure binary.imports is not None and is iterable before looping
    if is_pe and binary.imports:
        try:
            for imported_library in binary.imports:
                # FIX: Ensure imported_library is a PE.Import object and has entries
                if isinstance(imported_library, lief.PE.Import) and imported_library.entries:
                    for entry in imported_library.entries:
                        if entry.is_ordinal:
                            imports.append(f"#{entry.ordinal}") # Store ordinals as #ordinal
                        else:
                            imports.append(entry.name)
                elif not isinstance(imported_library, lief.PE.Import):
                    logging.warning(f"Unexpected object type in binary.imports for {filepath}: {type(imported_library)}")
        except Exception as e:
            logging.warning(f"Failed to extract PE imports from {filepath}: {e}")
    elif not is_pe:
        logging.info(f"Not a PE file, skipping PE-specific import extraction for {filepath}")
    else: # is_pe is True but binary.imports is empty or None
        logging.info(f"PE file {filepath} has no imports or imports could not be parsed.")


    return {
        "hash": hash_val,
        "strings": strings,
        "sections": sections_info,
        "overall_entropy": total_entropy,
        "imports": imports,
        "is_pe": is_pe,
        "type": "success"
    }


def extract_strings(path):
    """
    Extracts both ASCII and UTF-16LE printable strings from a file.
    Reads up to 10MB to avoid memory overload with large binaries.
    """
    try:
        with open(path, "rb") as f:
            content = f.read(10 * 1024 * 1024)  # Read up to 10MB

            # ASCII strings (e.g., readable text)
            # Match 4 or more printable ASCII characters
            ascii_strings = re.findall(rb'[\x20-\x7E]{4,}', content)
            
            # UTF-16LE strings (e.g., Windows wide-character encoded strings)
            # Match 4 or more pairs of (printable ASCII char + null byte)
            unicode_strings = re.findall(rb'(?:[\x20-\x7E]\x00){4,}', content)

            # Decode both sets safely
            ascii_decoded = [s.decode("utf-8", errors="ignore") for s in ascii_strings]
            unicode_decoded = [s.decode("utf-16le", errors="ignore") for s in unicode_strings]

            return ascii_decoded + unicode_decoded
    except Exception as e:
        logging.error(f"Error extracting strings from {path}: {e}")
        return []

def file_hash(path):
    """
    Computes MD5 hash of the given file (for unique identification).
    Efficiently reads the file in chunks to support large files.
    """
    try:
        hasher = hashlib.md5()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        logging.error(f"Error calculating hash for {path}: {e}")
        return "hash_calculation_error"

def calculate_raw_entropy(data):
    """
    Calculates the Shannon entropy of a given bytes object.
    """
    if not data:
        return 0.0

    entropy_sum = 0
    length = len(data)

    # Calculate frequency of each byte value
    frequency = [0] * 256
    for byte_value in data:
        frequency[byte_value] += 1

    # Calculate entropy
    for count in frequency:
        if count > 0:
            probability = float(count) / length
            entropy_sum -= probability * math.log(probability, 2)

    return entropy_sum
