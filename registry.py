"""
registry.py
-----------
This module contains the central application registry dictionary which holds
all dynamically registered network utility functions.
"""

application = {}

# Holds menu entries. Each entry is a dictionary with keys:
#   'category': A list representing the menu hierarchy.
#   'name': The display name of the module.
#   'help': A help string.
#   'callback': The function (or callable) to run when selected.
menu_registry = []
