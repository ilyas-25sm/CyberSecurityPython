import logging
import os
import yara
import traceback

# Path to the directory containing YARA rule files
YARA_RULE_DIRECTORIES = [r'C:/Program Files/Mirza/yara']

def initialize_yara_rules():
    """
    Initialize and compile YARA rules from the specified directories.
    This function processes all `.yar` files, compiles them individually, and as a combined set.
    """
    yara_rules_content = ""
    externals_defaults = {
        'filename': "",
        'filepath': "",
        'extension': "",
        'filetype': "",
        'md5': "",
        'owner': ""  # Added external identifier 'owner' for compatibility
    }
    compiled_rules = None

    # Process each directory containing YARA rules
    for yara_rule_directory in YARA_RULE_DIRECTORIES:
        if not os.path.exists(yara_rule_directory):
            logging.error(f"Directory not found: {yara_rule_directory}")
            continue

        logging.info(f"Processing YARA rules folder: {yara_rule_directory}")

        # Walk through each file in the directory
        for root, _, files in os.walk(yara_rule_directory):
            for file in files:
                yara_rule_file = os.path.join(root, file)
                try:
                    # Skip non-YARA files
                    if not file.endswith('.yar'):
                        logging.warning(f"Skipping non-YARA file: {file}")
                        continue

                    # Compile individual YARA rule
                    compiled_rule = yara.compile(filepath=yara_rule_file, externals=externals_defaults)
                    logging.info(f"Compiled YARA rule file successfully: {file}")

                    # Add rule content for combined compilation
                    with open(yara_rule_file, 'r', encoding='utf-8', errors='ignore') as f:
                        yara_rules_content += f.read() + "\n"

                except yara.SyntaxError as e:
                    logging.error(f"Syntax error in file {file}: {e}")
                except yara.Error as e:
                    logging.error(f"General YARA compilation error in file {file}: {e}")
                except Exception as e:
                    logging.error(f"Unexpected error in file {file}: {e}")
                    traceback.print_exc()

    # Compile all combined rules
    try:
        logging.info("Compiling all YARA rules from combined content.")
        compiled_rules = yara.compile(source=yara_rules_content, externals=externals_defaults)
        logging.info("All YARA rules compiled successfully.")

    except yara.SyntaxError as e:
        logging.error(f"Combined YARA rule compilation error (syntax): {e}")
    except yara.Error as e:
        logging.error(f"Combined YARA rule compilation error: {e}")
    except Exception as e:
        logging.error("Unexpected error during combined YARA rule compilation")
        traceback.print_exc()

    return compiled_rules

def save_compiled_rules(compiled_rules, output_file='C:/Program Files/Mirza/compiled_rules.yarc'):
    """
    Save compiled YARA rules to a file for future use.
    """
    try:
        if compiled_rules:
            compiled_rules.save(output_file)
            logging.info(f"Compiled YARA rules saved to {output_file}.")
        else:
            logging.warning("No compiled YARA rules to save.")
    except Exception as e:
        logging.error(f"Failed to save compiled YARA rules: {e}")
        traceback.print_exc()

# MAIN
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    compiled_rules = initialize_yara_rules()
    save_compiled_rules(compiled_rules)
