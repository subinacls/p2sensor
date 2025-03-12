"""
main.py
-------
Enhanced main entry point for the dynamic module application.
Features:
  - Automatically imports modules (any .py file in the directory/subdirectories).
  - Builds a hierarchical menu from registered metadata.
  - Provides a colored, interactive menu system.
  - After executing a test, returns to the menu.
  - Remembers user input and offers auto‑completion using Tab.
  - Logs any newly discovered domain/IP information.
  - Prompts user for additional tests against associated hosts.
"""

import os
import sys
import importlib.util
import importlib
import logging
from colorama import init, Fore, Style
import readline

# Holds methods of the application from modules imported to the framework for Interactive CLI
#    Useful when including functionality from aexternal modules imported into the framework
#    Exposed API or other use cases where integrations need to be created customized and or modified
#    Can be expanded by including additional modules

application = {}

# Holds menu entries. Each entry is a dictionary with keys:
#   'category': A list representing the menu hierarchy.
#   'name': The display name of the module.
#   'help': A help string.
#   'callback': The function (or callable) to run when selected.
menu_registry = []

# Initialize colorama (colors will auto-reset)
init(autoreset=True)

# Set up logging for additional target discovery
logging.basicConfig(
    filename="associated_targets.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Global list to store user inputs for auto-completion
user_inputs = []

def custom_completer(text, state):
    """
    Custom completer that returns previous user inputs starting with the given text.
    """
    options = [i for i in user_inputs if i.startswith(text)]
    if state < len(options):
        return options[state]
    else:
        return None

# Set up readline auto-completion
readline.set_completer(custom_completer)
readline.parse_and_bind("tab: complete")

def get_input(prompt):
    """
    Wrapper around input() that remembers non-empty inputs.
    """
    result = input(prompt)
    if result and result not in user_inputs:
        user_inputs.append(result)
    return result

# -----------------------
# Dynamic Import Function
# -----------------------
def import_all_modules(root_dir="."):
    """
    Recursively import all Python modules from the given root directory (excluding main.py).
    """
    for subdir, dirs, files in os.walk(root_dir):
        for filename in files:
            if filename.endswith(".py") and filename != os.path.basename(__file__):
                module_path = os.path.join(subdir, filename)
                rel_module = os.path.relpath(module_path, root_dir)
                module_name = rel_module[:-3].replace(os.path.sep, ".")
                try:
                    spec = importlib.util.spec_from_file_location(module_name, module_path)
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                except Exception as e:
                    print(Fore.RED + f"Error importing {module_path}: {e}", file=sys.stderr)

# -----------------------
# Menu System Functions
# -----------------------
def build_menu_tree(menu_entries):
    """
    Build a nested dictionary representing the menu hierarchy.
    Each node is a dictionary with keys:
      - '_entries': a list of entries at that level (if any).
      - Other keys represent subcategories.
    """
    tree = {}
    for entry in menu_entries:
        current = tree
        for category in entry["category"]:
            if category not in current:
                current[category] = {}
            current = current[category]
        if "_entries" not in current:
            current["_entries"] = []
        current["_entries"].append(entry)
    return tree

def display_menu(current_node):
    """
    Display the options at the current menu level.
    Only the current level is shown.
    """
    options = []
    # List subcategories first
    subcats = [k for k in current_node.keys() if k != "_entries"]
    for sub in sorted(subcats):
        options.append(("category", sub))
    # Then list module entries if any
    if "_entries" in current_node:
        for entry in current_node["_entries"]:
            options.append(("module", entry))
    # Print out the options with numbers in color.
    print(Fore.CYAN + Style.BRIGHT + "\nCurrent Menu:")
    for idx, (opt_type, value) in enumerate(options, start=1):
        if opt_type == "category":
            print(Fore.YELLOW + f"{idx}. {value}")
        else:
            print(Fore.GREEN + f"{idx}. {value['name']} - {value['help']}")
    print(Fore.MAGENTA + "0. Go Back")
    return options

def menu_navigation(menu_tree):
    """
    Navigate the hierarchical menu.
    Only the current menu level is displayed. Returns the selected module entry.
    """
    current_node = menu_tree
    history = []
    while True:
        options = display_menu(current_node)
        try:
            choice = int(get_input(Fore.WHITE + "Enter your choice: "))
        except ValueError:
            print(Fore.RED + "Invalid input. Please enter a number.")
            continue
        if choice == 0:
            if history:
                current_node = history.pop()
            else:
                # At top level, exit the menu navigation.
                return None
        elif 1 <= choice <= len(options):
            opt_type, value = options[choice - 1]
            if opt_type == "category":
                history.append(current_node)
                current_node = current_node[value]
            else:
                return value
        else:
            print(Fore.RED + "Choice out of range. Try again.")

def run_selected_module(entry):
    """
    Prompt for target input, run the module's callback,
    and then prompt to perform additional tests on associated hosts.
    """
    if entry is None:
        print(Fore.RED + "No module selected.")
        return
    user_target = get_input(Fore.WHITE + "Enter object (ie: help, IP/Domain, Command, Verb/Action): ")
    try:
        result = entry["callback"](user_target)
        print(Fore.GREEN + f"\nResult from {entry['name']}:\n{result}")
    except Exception as e:
        print(Fore.RED + f"Error running {entry['name']}: {e}")
        return

    # Log the initial target
    logging.info(f"Initial target for {entry['name']}: {user_target}")

    '''
    additional = get_input(Fore.WHITE + "Do you want to perform this test against associated hosts? (y/n): ").strip().lower()
    if additional == 'y':
        discovered = get_input(Fore.WHITE + "Enter associated target(s) separated by commas: ")
        associated_targets = [t.strip() for t in discovered.split(",") if t.strip()]
        for target in associated_targets:
            logging.info(f"Discovered associated target for {entry['name']}: {target}")
            try:
                additional_result = entry["callback"](target)
                print(Fore.GREEN + f"\nResult from {entry['name']} for {target}:\n{additional_result}")
            except Exception as e:
                print(Fore.RED + f"Error running {entry['name']} for {target}: {e}")
    '''
# -----------------------
# Main Loop
# -----------------------
def main():
    # Import all modules so they self-register.
    import_all_modules()

    # Build the menu tree from registered menu entries.
    menu_tree = build_menu_tree(menu_registry)

    # Main loop: continue to show menu after each execution.
    while True:
        print(Fore.BLUE + Style.BRIGHT + "\n=== Available Modules ===")
        selected_entry = menu_navigation(menu_tree)
        if selected_entry:
            print(Fore.BLUE + f"\nSelected module: {selected_entry['name']}")
            run_selected_module(selected_entry)
        else:
            print(Fore.BLUE + "Exiting the application.")
            break

if __name__ == "__main__":
    main()
