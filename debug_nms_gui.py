#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Debug wrapper for nms_gui.py that captures and prints any exceptions
"""

import sys
import traceback
import importlib.util

def check_module(module_name):
    """Check if a module can be imported and print its location if found."""
    try:
        spec = importlib.util.find_spec(module_name)
        if spec is None:
            print(f"Module {module_name} not found")
            return False
        else:
            print(f"Module {module_name} found at {spec.origin}")
            return True
    except Exception as e:
        print(f"Error checking for module {module_name}: {e}")
        return False

def main():
    # Check for required modules
    print("Checking for required modules:")
    check_module("tkinter")
    check_module("PIL")
    check_module("requests")
    check_module("pysnmp")
    check_module("pysnmp.hlapi")
    check_module("ping3")
    
    try:
        # Try to import the main function from nms_gui
        print("\nAttempting to import aruba_nms.nms_gui...")
        from aruba_nms import nms_gui
        print("Successfully imported module, now running main()...")
        nms_gui.main()
    except Exception as e:
        print(f"\nERROR running aruba_nms.nms_gui: {e}")
        print("\nTraceback:")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()