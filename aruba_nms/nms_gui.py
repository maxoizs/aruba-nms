#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nms.py - Network Monitoring System with GUI
Simple, single-file implementation with automatic settings management
"""

import os, sys, re, time, csv, json
from ipaddress import ip_address
from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, Canvas, filedialog
import base64, io
import json
import subprocess, platform, socket
import threading  # Add threading import

# Check required packages first
try:
    from PIL import Image, ImageTk, ImageDraw
except ImportError:
    print("ERROR: Missing package 'Pillow'. Please install with:")
    print("pip install pillow")
    sys.exit(1)

try:
    import requests
    import urllib3
except ImportError:
    print("ERROR: Missing packages 'requests' or 'urllib3'. Please install with:")
    print("pip install requests urllib3")
    sys.exit(1)

try:
    from ping3 import ping
except ImportError:
    print("ERROR: Missing package 'ping3'. Please install with:")
    print("pip install ping3")
    sys.exit(1)

import sys

try:
    print("Attempting to import pysnmp.hlapi...")
    from pysnmp.hlapi import (
        SnmpEngine, CommunityData, UdpTransportTarget, 
        ContextData, ObjectType, ObjectIdentity
    )
    from pysnmp.hlapi import getCmd
    print("Successfully imported pysnmp.hlapi")
except ImportError as e:
    print(f"Error importing pysnmp.hlapi: {e}")
    try:
        print("Attempting to install pysnmp...")
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pysnmp", "pysnmp-mibs"])
        print("Installation completed, now trying to import again...")
        from pysnmp.hlapi import (
            SnmpEngine, CommunityData, UdpTransportTarget, 
            ContextData, ObjectType, ObjectIdentity
        )
        from pysnmp.hlapi import getCmd
        print("Successfully imported pysnmp.hlapi after installation")
    except Exception as e:
        print(f"Failed to install or import pysnmp: {e}")
        print("Continuing without SNMP support...")
        # Define dummy classes to prevent errors
        class SnmpEngine: pass
        class CommunityData: pass
        class UdpTransportTarget: pass
        class ContextData: pass
        class ObjectType: pass
        class ObjectIdentity: pass
        def getCmd(*args, **kwargs): 
            print("SNMP not available")
            return []

# Custom Treeview class with cell-specific styling
class ColorTree(ttk.Treeview):
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)
        
        # Create a style object
        self.style = ttk.Style()
        self.style.configure("Treeview", foreground="black")
        
        # Initialize colors
        self.cell_colors = {}  # Store cell-specific colors
        
        # Status colors
        self.status_colors = {
            "Online": "green",
            "Failed": "orange",
            "Offline": "black",
            "Polling": "blue"
        }
        
        # Value threshold colors
        self.threshold_colors = {
            "red": "#FF0000",
            "orange": "#FFA500"
        }
        
        # Configure blink tag (no color, just for blinking animation)
        self.tag_configure("blink")
            
    def item(self, item, option=None, **kw):
        """Override item method to handle both get and set operations"""
        if option:
            return super().item(item, option)
        elif kw:
            return super().item(item, **kw)
        else:
            return super().item(item)
            
    def _set_cell_color(self, item, column, color):
        """Set color for a specific cell"""
        # Store the color in our dictionary using item and column as key
        key = f"{item}_{column}"
        self.cell_colors[key] = color
        
        # Create a binding for the cell to change its color when drawn
        def _on_draw(event):
            tree = event.widget
            item_id = tree.identify_row(event.y)
            column = tree.identify_column(event.x)
            if item_id and column:
                col_num = int(column[1]) - 1  # Convert #1 to 0, #2 to 1, etc.
                cell_key = f"{item_id}_{col_num}"
                if cell_key in self.cell_colors:
                    bbox = tree.bbox(item_id, column)
                    if bbox:
                        # Change text color for just this cell
                        tree.item(item_id, values=tree.item(item_id)["values"])
                        tree.tag_configure(cell_key, foreground=self.cell_colors[cell_key])
                        tree.tag_add(cell_key, item_id)
                        
        self.bind('<Expose>', _on_draw)
    
    def set_blink(self, item, should_blink):
        """Set or remove blink tag for an item"""
        try:
            current_tags = list(self.item(item, 'tags') or ())
            if should_blink and 'blink' not in current_tags:
                current_tags.append('blink')
                self.item(item, tags=tuple(current_tags))
            elif not should_blink and 'blink' in current_tags:
                current_tags.remove('blink')
                self.item(item, tags=tuple(current_tags))
        except Exception as e:
            print(f"Error in set_blink: {str(e)}")
            
    def clear_cell_colors(self, item):
        """Clear all cell colors for an item"""
        keys_to_remove = [k for k in self.cell_colors.keys() if k.startswith(f"{item}_")]
        for k in keys_to_remove:
            del self.cell_colors[k]
        
    def get_child_by_value(self, value, column):
        """Find a child item by its value in a specific column"""
        for item in self.get_children():
            if str(self.item(item)['values'][column]) == str(value):
                return item
        return None

# Settings file path
SETTINGS_PATH = os.path.join(os.path.dirname(__file__), 'nms_settings.json')

# Settings Dialog Class
class SettingsDialog:
    def __init__(self, parent, api_user="", api_pass="", snmp_comm="public"):
        self.result = None
        
        # Create the dialog window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Settings")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Make dialog modal
        self.dialog.focus_set()
        
        # Create and pack a frame for our widgets
        frame = ttk.Frame(self.dialog, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # API User
        ttk.Label(frame, text="API Username:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.api_user_entry = ttk.Entry(frame, width=30)
        self.api_user_entry.insert(0, api_user)
        self.api_user_entry.grid(row=0, column=1, sticky=tk.EW, pady=5)
        self.api_user_entry.bind('<Return>', lambda e: self.api_pass_entry.focus())
        
        # API Password
        ttk.Label(frame, text="API Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.api_pass_entry = ttk.Entry(frame, width=30, show="*")
        self.api_pass_entry.insert(0, api_pass)
        self.api_pass_entry.grid(row=1, column=1, sticky=tk.EW, pady=5)
        self.api_pass_entry.bind('<Return>', lambda e: self.snmp_entry.focus())
        
        # SNMP Community
        ttk.Label(frame, text="SNMP Community:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.snmp_entry = ttk.Entry(frame, width=30)
        self.snmp_entry.insert(0, snmp_comm)
        self.snmp_entry.grid(row=2, column=1, sticky=tk.EW, pady=5)
        self.snmp_entry.bind('<Return>', lambda e: self.ok())
        
        # Buttons frame
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        # OK and Cancel buttons
        self.ok_button = ttk.Button(button_frame, text="OK", command=self.ok)
        self.ok_button.pack(side=tk.LEFT, padx=5)
        
        self.cancel_button = ttk.Button(button_frame, text="Cancel", command=self.cancel)
        self.cancel_button.pack(side=tk.LEFT, padx=5)
        
        # Configure grid
        frame.columnconfigure(1, weight=1)
        
        # Bind Enter key to OK for the entire dialog
        self.dialog.bind('<Return>', lambda e: self.ok())
        self.dialog.bind('<Escape>', lambda e: self.cancel())
        
        # Set initial focus to username field
        self.api_user_entry.focus()
        
        # Center the dialog on parent window
        self.dialog.update_idletasks()
        parent_x = parent.winfo_x()
        parent_y = parent.winfo_y()
        parent_width = parent.winfo_width()
        parent_height = parent.winfo_height()
        dialog_width = self.dialog.winfo_width()
        dialog_height = self.dialog.winfo_height()
        x = parent_x + (parent_width - dialog_width) // 2
        y = parent_y + (parent_height - dialog_height) // 2
        self.dialog.geometry(f"+{x}+{y}")
        
        # Wait for dialog to close
        self.dialog.wait_window()
    
    def ok(self):
        """Save the entered values and close dialog"""
        self.result = {
            "api_user": self.api_user_entry.get(),
            "api_pass": self.api_pass_entry.get(),
            "snmp_comm": self.snmp_entry.get()
        }
        self.dialog.destroy()
    
    def cancel(self):
        """Close dialog without saving"""
        self.dialog.destroy()

# --- Robust reachability check (Windows-friendly) ---
import subprocess, platform, socket

def _tcp_probe(ip: str, ports=(443, 22, 80), timeout=0.4) -> bool:
    for p in ports:
        try:
            with socket.create_connection((ip, p), timeout=timeout):
                return True
        except Exception:
            continue
    return False

def best_ping(ip: str, timeout_ms: int = 1000) -> bool:
    """
    Prefer OS ping (very reliable on Windows). Fallback to ping3 and short TCP probes.
    Returns True if host appears reachable, else False.
    """
    system = platform.system().lower()

    # 1) System ping
    try:
        if system.startswith('win'):
            # Windows: -n 1 (one echo), -w ms timeout
            res = subprocess.run(["ping", "-n", "1", "-w", str(timeout_ms), ip],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if res.returncode == 0:
                return True
        else:
            # Linux/mac: -c 1 (one echo), -W seconds (Linux)
            res = subprocess.run(["ping", "-c", "1", "-W", str(int(timeout_ms/1000) or 1), ip],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if res.returncode == 0:
                return True
    except Exception:
        pass

    # 2) ping3 (non-privileged)
    try:
        rtt = ping(ip, timeout=timeout_ms/1000.0, privileged=False)
        if rtt not in (None, False):
            return True
    except Exception:
        pass

    # 3) Short TCP probes to common ports
    return _tcp_probe(ip)

from pysnmp.hlapi import *

urllib3.disable_warnings()

# ---------------- Configuration ----------------
REFRESH_SEC = 60.0
MAX_WORKERS = 20

# Default IP file paths (try multiple locations)
DEFAULT_IP_FILE = os.path.join(os.path.dirname(__file__), 'data', 'ip.txt')
if not os.path.exists(DEFAULT_IP_FILE):
    # Try alternate locations
    alt_paths = [
        os.path.join(os.path.dirname(__file__), 'ips.txt'),
        os.path.join(os.path.dirname(__file__), 'ip.txt'),
        os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ip.txt')
    ]
    for path in alt_paths:
        if os.path.exists(path):
            DEFAULT_IP_FILE = path
            break
    print(f"Using IP file: {DEFAULT_IP_FILE}")

# Column definitions
COLUMNS = [
    {"id": "icon", "text": "", "width": 30},  # Icon column (0)
    {"id": "status", "text": "Status", "width": 70},  # Status column (1)
    {"id": "ip", "text": "IP Address", "width": 100},  # IP column (2)
    {"id": "name", "text": "System Name", "width": 120},  # Name column (3)
    {"id": "vendor", "text": "Vendor", "width": 80},  # Vendor column (4)
    {"id": "model", "text": "Model", "width": 100},  # Model column (5)
    {"id": "serial", "text": "Serial", "width": 100},  # Serial column (6)
    {"id": "cpu", "text": "CPU %", "width": 50},  # CPU column (7)
    {"id": "mem", "text": "Mem %", "width": 50},  # Memory column (8)
    {"id": "uptime", "text": "Uptime", "width": 80}  # Uptime column (9)
]

# Status definitions with icons
STATUS_TYPES = {
    "Online": {"color": None, "blink": False},  # No special color for online
    "Offline": {"color": None, "blink": True},  # Offline blinks but no color
    "Failed": {"color": None, "blink": False},  # No color or blink for failed
    "Off-On": {"color": None, "blink": True},   # Transitional state blinks
    "Polling": {"color": None, "blink": True}   # Polling status blinks
}

# ---------------- SNMP helpers ----------------
def format_snmp_uptime(ticks):
    """Convert SNMP uptime ticks (1/100th seconds) to 'Xd Yh Zm' format"""
    try:
        # Convert ticks to seconds
        seconds = int(ticks) / 100
        
        # Calculate components
        days = int(seconds // (24 * 3600))
        seconds = seconds % (24 * 3600)
        hours = int(seconds // 3600)
        seconds = seconds % 3600
        minutes = int(seconds // 60)
        
        # Format as Xd Yh Zm
        return f"{days}d {hours}h {minutes}m"
    except (ValueError, TypeError):
        return "N/A"

def snmp_get_value(ip, comm, oid_string, timeout=2, retries=2):
    """Enhanced SNMP GET with better error handling and debugging"""
    try:
        # Create SNMP GET request with SNMPv2c
        errorIndication, errorStatus, errorIndex, varBinds = next(
            getCmd(SnmpEngine(),
                  CommunityData(comm, mpModel=1),  # mpModel=1 for SNMPv2c
                  UdpTransportTarget((ip, 161), timeout=timeout, retries=retries),
                  ContextData(),
                  ObjectType(ObjectIdentity(oid_string)))
        )
        
        if errorIndication:
            print(f"SNMP error for {ip}: {errorIndication}")
            return None
        elif errorStatus:
            print(f"SNMP error for {ip}: {errorStatus}")
            return None
            
        # Process response
        if not varBinds:
            print(f"No SNMP response from {ip}")
            return None
            
        for varBind in varBinds:
            val = varBind[1].prettyPrint()
            if "No Such" in val:
                #print(f"SNMP OID not found for {ip}: {oid_string}")
                return None
            return val
            
    except Exception as e:
        #print(f"SNMP exception for {ip}: {str(e)}")
        if hasattr(e, '__traceback__'):
            import traceback
            traceback.print_exc()
        return None

def detect_vendor(descr):
    if not descr: return "Unknown"
    d=descr.lower()
    if "aruba" in d or "aos-cx" in d: return "Aruba CX"
    if "cisco" in d: return "Cisco"
    if "huawei" in d: return "Huawei"
    return "Unknown"

def model_from_descr(descr):
    if not descr: return "Unknown"
    m=re.search(r'\b(62\d{2}F|63\d{2}F|81\d{2}-\S+)\b', descr)
    if m: return m.group(1)
    fb=re.search(r'\b([A-Z0-9\-]{4,})\b', descr)
    return fb.group(1) if fb else "Unknown"

# ---------------- Aruba REST ----------------
def api_login(sess, base, u, p):
    try:
        r=sess.post(f"{base}/login", data={"username":u,"password":p},
                    headers={"Content-Type":"application/x-www-form-urlencoded"},
                    timeout=5, verify=False)
        if r.status_code==200: return r
        r=sess.post(f"{base}/login", json={"username":u,"password":p}, timeout=5, verify=False)
        if r.status_code==200: return r
    except Exception: return None
    return None

def _get(sess, base, url):
    try:
        full=url if url.startswith("http") else f"{base}{url}"
        r=sess.get(full, timeout=5, verify=False)
        if r.status_code==200 and "application/json" in r.headers.get("Content-Type",""):
            return r.json()
    except Exception: return None
    return None

def aruba_api(ip,u,p):
    try:
        sess=requests.Session(); sess.verify=False
        base=login=ver=None
        
        # Try different API versions
        for v in ["10.12","10.08","10.04"]:
            b=f"https://{ip}/rest/v{v}"
            #print(f"API Debug - Trying {ip} with version {v}")  # Debug log
            lr=api_login(sess,b,u,p)
            if lr: 
                base=b
                login=lr
                ver=v
                #print(f"API Debug - Login successful for {ip} with version {v}")  # Debug log
                break
                
        if not base: 
            #print(f"API Debug - Failed to login to {ip} with any version")  # Debug log
            return None
            
        csrf=login.headers.get("X-CSRF-TOKEN")
        if csrf: sess.headers.update({"X-CSRF-TOKEN":csrf})
    except Exception as e:
        #print(f"API Debug - Login error for {ip}: {str(e)}")
        return None

    # Try different API endpoints to get system info
    # Different endpoints for different switch models
    try:
        endpoints = [
        "/system?attributes=product_info,hostname,platform_name,platform_os_version",
        "/system",  # Basic system info
        "/system/status",  # Status endpoint which might have hostname
        "/system/subsystems",  # Subsystems info
        "/system/switches",  # 6200 specific endpoint
        "/system/switch_info",  # Alternative switch info endpoint
        "/management/status",  # Management status might have hostname
        "/system/mgmt_intf" # Management interface info
    ]
    except Exception as e:
        #print(f"API Debug - Error setting up endpoints for {ip}: {str(e)}")
        return None
        
    hostname = serial = model = "N/A"
    sysinfo = None
    
    try:
        for endpoint in endpoints:
            try:
                data = _get(sess, base, endpoint)
                #print(f"API Debug - {ip} endpoint {endpoint}:", data)  # Debug log
                
                if data:
                    #print(f"API Debug - {ip} Data structure:", data)  # Debug full data structure
                    
                    # Try to get hostname from various fields and nested structures
                    if isinstance(data, dict):
                        # Direct fields
                        if "hostname" in data:
                            hostname = data["hostname"]
                            #print(f"API Debug - Found hostname in direct field: {hostname}")
                            break
                        elif "name" in data:
                            hostname = data["name"]
                            #print(f"API Debug - Found name in direct field: {hostname}")
                            break
                        elif "system_name" in data:
                            hostname = data["system_name"]
                            #print(f"API Debug - Found system_name in direct field: {hostname}")
                            break
                        
                        # Check nested structures
                        if "mgmt_config" in data and isinstance(data["mgmt_config"], dict):
                            if "hostname" in data["mgmt_config"]:
                                hostname = data["mgmt_config"]["hostname"]
                                #print(f"API Debug - Found hostname in mgmt_config: {hostname}")
                                break
                            
                    # For 6200 series specific structure
                    if "switches" in data and isinstance(data["switches"], list):
                        for switch in data["switches"]:
                            if isinstance(switch, dict) and "hostname" in switch:
                                hostname = switch["hostname"]
                                #print(f"API Debug - Found hostname in switches array: {hostname}")
                                break
                    
                    # Store system info for later if this is the main endpoint
                    if "product_info" in data:
                        sysinfo = data
            except Exception as e:
                #print(f"API Debug - Error accessing endpoint {endpoint} for {ip}: {str(e)}")
                continue
    except Exception as e:
        #print(f"API Debug - Error processing endpoints for {ip}: {str(e)}")
        return None
            
    # Get product info if we found it
    product = sysinfo.get("product_info") if sysinfo else None
    if product:
        serial = product.get("serial_number", "N/A")
        model = sysinfo.get("platform_name", "N/A")
    elif sysinfo:
        model = sysinfo.get("platform_name", "N/A")
        serial = sysinfo.get("system_mac", "N/A")

    uptime="N/A"
    status=_get(sess,base,"/system?selector=status")
    if status and "boot_time" in status:
        try:
            sec=int(time.time())-int(status["boot_time"])
            d=sec//86400; h=(sec%86400)//3600; m=(sec%3600)//60
            uptime=f"{d}d {h}h {m}m"
        except Exception: pass

    cpu=mem="N/A"
    subs=_get(sess,base,"/system/subsystems")
    if subs:
        for _,url in subs.items():
            s=_get(sess,base,url if url.startswith("http") else f"https://{ip}{url}")
            if not s: continue
            if "product_info" in s:
                serial=s["product_info"].get("serial_number",serial)
                model=s["product_info"].get("product_name",model)
            if "resource_utilization" in s:
                u=s["resource_utilization"]
                c=u.get("cpu") or u.get("cpu_avg_1_min")
                m=u.get("memory") or u.get("memory_utilization")
                if isinstance(c,(int,float)): cpu=f"{c}%"
                if isinstance(m,(int,float)): mem=f"{m}%"
            if cpu!="N/A" or mem!="N/A": break
    return {"vendor":"Aruba CX","model":model,"serial":serial,"uptime":uptime,"cpu":cpu,"memory":mem,"hostname":hostname}

# ---------------- SNMP fallback ----------------
def snmp_data(ip, comm):
    """Enhanced SNMP data collection with more OIDs and better error handling"""
    try:
        # System description is mandatory - if this fails, SNMP is not working
        descr = snmp_get_value(ip, comm, "1.3.6.1.2.1.1.1.0")  # sysDescr
        if not descr:
            print(f"SNMP: Could not get system description from {ip}")
            return None
            
        # Get system name from sysName OID
        sys_name = snmp_get_value(ip, comm, "1.3.6.1.2.1.1.5.0")  # sysName
        if not sys_name or sys_name == "N/A":
            # Try hostname OID as backup
            sys_name = snmp_get_value(ip, comm, "1.3.6.1.2.1.1.6.0") or "N/A"  # sysLocation
        
        # Clean up system name if needed
        if sys_name and sys_name != "N/A":
            sys_name = sys_name.strip().strip('"').strip()
            if not sys_name:
                sys_name = "N/A"
                
        uptime_ticks = snmp_get_value(ip, comm, "1.3.6.1.2.1.1.3.0")  # sysUpTime
        sys_uptime = format_snmp_uptime(uptime_ticks) if uptime_ticks != "N/A" else "N/A"
        
        # Try to get CPU utilization from different OIDs (vendor specific)
        cpu = "N/A"
        for cpu_oid in [
            "1.3.6.1.4.1.2021.11.11.0",  # UCD-SNMP-MIB::ssCpuIdle.0
            "1.3.6.1.4.1.9.9.109.1.1.1.1.3.1",  # CISCO-PROCESS-MIB
            "1.3.6.1.2.1.25.3.3.1.2.1",  # HOST-RESOURCES-MIB
        ]:
            cpu_val = snmp_get_value(ip, comm, cpu_oid)
            if cpu_val and cpu_val.isdigit():
                cpu = f"{cpu_val}%"
                break
        
        # Try to get memory utilization
        mem = "N/A"
        mem_total = snmp_get_value(ip, comm, "1.3.6.1.2.1.25.2.2.0")  # hrMemorySize
        mem_used = snmp_get_value(ip, comm, "1.3.6.1.2.1.25.2.3.1.6.1")
        if mem_total and mem_used and mem_total.isdigit() and mem_used.isdigit():
            try:
                mem_percent = (int(mem_used) / int(mem_total)) * 100
                mem = f"{mem_percent:.1f}%"
            except:
                pass
                
        # Try to get serial number from different OIDs
        serial = "N/A"
        for serial_oid in [
            "1.3.6.1.2.1.47.1.1.1.1.11.1",  # ENTITY-MIB
            "1.3.6.1.4.1.9.3.6.3.0",  # CISCO-PRODUCTS-MIB
        ]:
            serial_val = snmp_get_value(ip, comm, serial_oid)
            if serial_val and serial_val != "N/A":
                serial = serial_val
                break
                
        return {
            "vendor": detect_vendor(descr),
            "model": model_from_descr(descr),
            "serial": serial,
            "uptime": sys_uptime,
            "cpu": cpu,
            "memory": mem,
            "hostname": sys_name  # Use the system name we collected
        }
    except Exception as e:
        print(f"SNMP data collection error for {ip}: {str(e)}")
        return None
    
    return {
        "vendor": detect_vendor(descr),
        "model": model_from_descr(descr),
        "serial": serial,
        "uptime": sys_uptime,
        "cpu": cpu,
        "memory": mem
    }

# ---------------- Status handling ----------------
def norm_status(s):
    """Normalize device status strings to standard values"""
    # Handle empty/invalid cases
    if not s or s == "N/A" or s == "..." or s is None:
        return "Failed"
    
    try:
        # Normalize string for comparison
        s = str(s).strip().lower()
        
        # Check for specific status values
        if s == "online" or s.startswith("on"):
            return "Online"
        if s.startswith("off"):
            return "Off-On" if "on" in s else "Offline"
        if s == "failed" or s.startswith("fail"):
            return "Failed"
        if s == "polling" or s.startswith("poll"):
            return "Polling"
            
        # Default to Failed for unrecognized statuses
        return "Failed"
    except Exception:
        # Return Failed on any error in processing
        return "Failed"

# ---------------- Device worker ----------------
def collect(ip,u,p,comm)->Dict[str,Any]:
    reachable = best_ping(ip, timeout_ms=1000)
    
    # Check for previously known device to detect state transitions
    last_status = None
    
    if not reachable:
        status = "Offline"
        return {"ip":ip,"status":status,"hostname":"N/A","cpu":"N/A","mem":"N/A","uptime":"N/A",
                "vendor":"N/A","model":"N/A","serial":"N/A"}
    
    # Try API first if credentials are provided
    if u and p:
        d = aruba_api(ip,u,p)
        if d:
            # Check for transitioning device (e.g., recently booted)
            uptime = d.get("uptime", "N/A")
            # If uptime is very low, device might be in transition
            if isinstance(uptime, str) and "0d" in uptime and "0h" in uptime and "m" in uptime:
                try:
                    # Extract minutes
                    mins = int(uptime.split("m")[0].strip().split(" ")[-1])
                    if mins < 5:  # If device booted less than 5 minutes ago
                        return {"ip":ip,"status":"Off-On","cpu":d.get("cpu","N/A"),"mem":d.get("memory","N/A"),
                                "uptime":uptime,"vendor":d.get("vendor","N/A"),
                                "model":d.get("model","N/A"),"serial":d.get("serial","N/A")}
                except (ValueError, IndexError):
                    pass  # If parsing fails, continue with normal status
                    
            return {"ip":ip,"status":"Online","hostname":d.get("hostname","N/A"),
                    "cpu":d.get("cpu","N/A"),"mem":d.get("memory","N/A"),
                    "uptime":d.get("uptime","N/A"),"vendor":d.get("vendor","N/A"),
                    "model":d.get("model","N/A"),"serial":d.get("serial","N/A")}
    
    # Try SNMP if API failed or no credentials
    d = snmp_data(ip,comm)
    if d:
        return {"ip":ip,"status":"Online","hostname":d.get("hostname","N/A"),
                "cpu":d.get("cpu","N/A"),"mem":d.get("memory","N/A"),
                "uptime":d.get("uptime","N/A"),"vendor":d.get("vendor","N/A"),
                "model":d.get("model","N/A"),"serial":d.get("serial","N/A")}
                
    return {"ip":ip,"status":"Failed","hostname":"N/A","cpu":"N/A","mem":"N/A","uptime":"N/A",
            "vendor":"N/A","model":"N/A","serial":"N/A"}

# ---------------- Polling ----------------
def read_ips(ip_file_path):
    """Read IP addresses from a file path"""
    with open(ip_file_path, "r", encoding="utf-8") as f:
        ips = [ln.strip() for ln in f if ln.strip()]
    return sorted(ips, key=lambda x: ip_address(x))

def poll_all(ips, u, p, comm, previous_states=None):
    """Poll all devices with awareness of previous states"""
    previous_states = previous_states or {}
    
    # First, return a placeholder for each IP to display them all
    for ip in ips:
        yield {
            "ip": ip,
            "status": "Polling",  # Special status for IPs being polled
            "cpu": "...", "mem": "...", "uptime": "...",
            "vendor": "...", "model": "...", "serial": "..."
        }
    
    # Then start polling each IP asynchronously
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = {ex.submit(collect, ip, u, p, comm): ip for ip in ips}
        for fut in as_completed(futs):
            ip = futs[fut]
            try:
                result = fut.result()
                # Check for state transitions
                if ip in previous_states:
                    prev = previous_states[ip]
                    curr = result.get("status")
                    
                    # Detect offline to online transition
                    if prev == "Offline" and curr == "Online":
                        result["status"] = "Off-On"
                
                # Update previous state for this IP
                previous_states[ip] = result.get("status")
                
                yield result
            except Exception:
                result = {
                    "ip": ip,
                    "status": "Failed",
                    "cpu": "N/A", "mem": "N/A", "uptime": "N/A",
                    "vendor": "N/A", "model": "N/A", "serial": "N/A"
                }
                
                # Update previous state for this IP
                previous_states[ip] = "Failed"
                
                yield result

# ---------------- Sorting & counts ----------------
def sort_devs(devs):
    # Create a copy of the devices list to avoid modifying the original
    sorted_devs = []
    for d in devs:
        dev_copy = d.copy()
        # Normalize status with proper error handling
        status = dev_copy.get("status", "")
        dev_copy["status"] = norm_status(status)
        sorted_devs.append(dev_copy)

    # Default sorting order (can be overridden by column sorting)
    order = {"Offline":0, "Failed":1, "Off-On":2, "Online":3, "Polling":4}
    return sorted(sorted_devs, key=lambda d:(order.get(d["status"],5), ip_address(d["ip"])))

def counts(devs):
    t = len(devs)
    # Create a copy of devices to avoid modifying the original list
    norm_devs = []
    for d in devs:
        # Create a copy of the device dict
        dev_copy = d.copy()
        # Ensure status is properly normalized for counting
        if "status" in dev_copy:
            dev_copy["status"] = norm_status(dev_copy.get("status", ""))
        norm_devs.append(dev_copy)
    
    # Count based on normalized statuses
    o = sum(1 for d in norm_devs if d.get("status") == "Online")
    f = sum(1 for d in norm_devs if d.get("status") == "Failed")
    off = sum(1 for d in norm_devs if d.get("status") == "Offline")
    p = sum(1 for d in norm_devs if d.get("status") == "Polling")
    
    return t,o,f,off,p

# ---------------- GUI Application ----------------
class NmsApp:
    def __init__(self, root):
        # Store root and destroy any existing widgets
        self.root = root
        for widget in root.winfo_children():
            widget.destroy()
            
        # Set window title with emoji
        root.title("🔍 Aruba NMS Live Monitor")
        root.geometry("900x600")  # Set window size to show table content better
        # Create and set taskbar icon
        icon_size = 64
        icon = Image.new('RGBA', (icon_size, icon_size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(icon)
        # Draw circular background
        draw.ellipse([4, 4, icon_size-4, icon_size-4], fill='#0066cc')
        # Add magnifying glass effect
        draw.ellipse([12, 12, icon_size-12, icon_size-12], fill='#ffffff')
        draw.ellipse([16, 16, icon_size-16, icon_size-16], fill='#0066cc')
        # Add handle
        draw.rectangle([icon_size-22, icon_size-26, icon_size-8, icon_size-12], fill='#ffffff')
        # Convert to PhotoImage and set as window icon
        icon_photo = ImageTk.PhotoImage(icon)
        root.iconphoto(True, icon_photo)
        
        # Initialize variables
        self.refresh_thread = None
        self.results_queue = []
        self.batch_timer = None
        self.refresh_timer = None
        self.blink_timer = None
        self.blink_state = False
        self.is_shutting_down = False  # Flag to track shutdown state
        
        # Bind the window close event
        root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Initialize UI variables first
        self.setup_gui_variables()
        
        # Initialize settings
        self.init_settings()
        
        # Create and layout GUI elements
        self.setup_gui_layout()
        
        # Handle startup state
        self.handle_startup()
        
        # Start blinking timer
        self.toggle_blink()
    
    def setup_gui_variables(self):
        """Initialize GUI variables"""
        # Status variables
        self.status_var = tk.StringVar(value="Ready")
        self.refresh_var = tk.StringVar(value="Last refresh: —")
        
        # Summary variables with initial values
        self.total_var = tk.StringVar(value="--")
        self.online_var = tk.StringVar(value="--")
        self.failed_var = tk.StringVar(value="--")
        self.offline_var = tk.StringVar(value="--")
        
        # Sorting variables
        self.sort_column = "ip"
        self.sort_reverse = False
        
        # Device tracking
        self.devices = []
        self.first_pass_done = False
        self.previous_states = {}
        
        # Create status icons
        self.icons = self.create_status_icons()
    
    def setup_gui_layout(self):
        """Create and layout GUI elements"""
        # Single main frame
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Summary frame at the top
        self.summary_frame = ttk.Frame(self.main_frame)
        self.summary_frame.pack(fill=tk.X, pady=(0, 5))
        
        # Summary frame with sections
        summary_frame_inner = ttk.Frame(self.summary_frame)
        summary_frame_inner.pack(side=tk.LEFT, padx=5, fill=tk.X)

        # Total Nodes
        total_frame = ttk.Frame(summary_frame_inner)
        total_frame.pack(side=tk.LEFT, padx=5)
        self.total_icon = tk.Label(total_frame, text="📊", font=('Segoe UI Emoji', 11), foreground='#0078D7')
        self.total_icon.pack(side=tk.LEFT)
        ttk.Label(total_frame, text=" Total Nodes:", font=('Helvetica', 10, 'bold')).pack(side=tk.LEFT)
        self.total_var = tk.StringVar(value="--")
        ttk.Label(total_frame, textvariable=self.total_var, font=('Helvetica', 10, 'bold')).pack(side=tk.LEFT)

        # Separator
        ttk.Label(summary_frame_inner, text=" | ").pack(side=tk.LEFT)

        # Online
        online_frame = ttk.Frame(summary_frame_inner)
        online_frame.pack(side=tk.LEFT, padx=5)
        self.online_icon = tk.Label(online_frame, text="✅", font=('Segoe UI Emoji', 11), foreground='#107C10')
        self.online_icon.pack(side=tk.LEFT)
        ttk.Label(online_frame, text=" Online:", font=('Helvetica', 10, 'bold')).pack(side=tk.LEFT)
        self.online_var = tk.StringVar(value="--")
        ttk.Label(online_frame, textvariable=self.online_var, font=('Helvetica', 10, 'bold')).pack(side=tk.LEFT)

        # Separator
        ttk.Label(summary_frame_inner, text=" | ").pack(side=tk.LEFT)

        # Failed
        failed_frame = ttk.Frame(summary_frame_inner)
        failed_frame.pack(side=tk.LEFT, padx=5)
        self.failed_icon = tk.Label(failed_frame, text="⚠️", font=('Segoe UI Emoji', 11), foreground='#FFB900')
        self.failed_icon.pack(side=tk.LEFT)
        ttk.Label(failed_frame, text=" Failed:", font=('Helvetica', 10, 'bold')).pack(side=tk.LEFT)
        self.failed_var = tk.StringVar(value="--")
        ttk.Label(failed_frame, textvariable=self.failed_var, font=('Helvetica', 10, 'bold')).pack(side=tk.LEFT)

        # Separator
        ttk.Label(summary_frame_inner, text=" | ").pack(side=tk.LEFT)

        # Offline
        offline_frame = ttk.Frame(summary_frame_inner)
        offline_frame.pack(side=tk.LEFT, padx=5)
        self.offline_icon = tk.Label(offline_frame, text="❌", font=('Segoe UI Emoji', 11), foreground='#E81123')
        self.offline_icon.pack(side=tk.LEFT)
        ttk.Label(offline_frame, text=" Offline:", font=('Helvetica', 10, 'bold')).pack(side=tk.LEFT)
        self.offline_var = tk.StringVar(value="--")
        ttk.Label(offline_frame, textvariable=self.offline_var, font=('Helvetica', 10, 'bold')).pack(side=tk.LEFT)

        # Refresh time on the right
        self.refresh_label = ttk.Label(self.summary_frame, textvariable=self.refresh_var)
        self.refresh_label.pack(side=tk.RIGHT, padx=(0, 5))
        
        # Create control frame below summary
        self.control_frame = ttk.Frame(self.main_frame)
        self.control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Add buttons
        self.open_ip_btn = ttk.Button(self.control_frame, text="Open", command=self.open_ip_file)
        self.open_ip_btn.pack(side=tk.LEFT, padx=5)
        
        self.refresh_btn = ttk.Button(self.control_frame, text="Re-Sync", command=self.refresh_data)
        self.refresh_btn.pack(side=tk.RIGHT, padx=5)
        
        self.export_btn = ttk.Button(self.control_frame, text="Export", command=self.export_to_csv)
        self.export_btn.pack(side=tk.RIGHT, padx=5)
        
        self.settings_btn = ttk.Button(self.control_frame, text="Settings", command=self.open_settings)
        self.settings_btn.pack(side=tk.RIGHT, padx=5)
        
        # Create Treeview for data display with scrollbar
        self.tree_frame = ttk.Frame(self.main_frame)
        self.tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add vertical scrollbar
        self.scrollbar = ttk.Scrollbar(self.tree_frame)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Create horizontal scrollbar
        self.h_scrollbar = ttk.Scrollbar(self.tree_frame, orient=tk.HORIZONTAL)
        self.h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)

        # Create custom Treeview with both scrollbars
        self.tree = ColorTree(self.tree_frame, 
                            yscrollcommand=self.scrollbar.set,
                            xscrollcommand=self.h_scrollbar.set,
                            selectmode='browse')
        self.scrollbar.config(command=self.tree.yview)
        self.h_scrollbar.config(command=self.tree.xview)
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        # Define columns
        column_ids = [col["id"] for col in COLUMNS[1:]]  # Skip the icon column
        self.tree['columns'] = column_ids
        self.tree.column('#0', width=40, stretch=tk.NO, anchor=tk.CENTER)
        self.tree.heading('#0', text='')
        
        # Set column headings and widths
        for col in COLUMNS[1:]:
            self.tree.column(col["id"], width=col["width"], anchor=tk.W)
            self.tree.heading(col["id"], text=col["text"], anchor=tk.CENTER,
                            command=lambda col_id=col["id"]: self.sort_by_column(col_id))
        
        # Style configuration
        style = ttk.Style()
        style.configure("Treeview", rowheight=24)
        
        # Enable ttk tree column colors
        style.map("Treeview",
            foreground=[("selected", "#ffffff")],
            background=[("selected", "#0078d7")])
        
        # Configure tags for CPU and Memory columns with colors
        # Warning (orange) color
        self.tree.tag_configure("cpu_orange", foreground="#FF8C00")  # Dark orange for CPU warning
        self.tree.tag_configure("mem_orange", foreground="#FF8C00")  # Dark orange for Memory warning
        
        # Critical (red) color
        self.tree.tag_configure("cpu_red", foreground="#FF0000")     # Red for CPU critical
        self.tree.tag_configure("mem_red", foreground="#FF0000")     # Red for Memory critical
        
        # Status bar at the bottom
        self.status_bar = ttk.Label(self.main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(fill=tk.X, padx=5, pady=2)
    
    def init_settings(self):
        """Initialize settings from file or with defaults"""
        # Load settings if they exist
        if os.path.exists(SETTINGS_PATH):
            settings = self._load_settings()
            self.api_user = settings.get("api_user", "")
            self.api_pass = settings.get("api_pass", "")
            self.snmp_comm = settings.get("snmp_comm", "public")
            
            # Only use saved IP file path if it still exists
            saved_ip_path = settings.get("last_ip_file")
            if saved_ip_path and os.path.exists(saved_ip_path):
                self.ip_file_path = saved_ip_path
                print(f"Loaded IP file path: {self.ip_file_path}")
            else:
                self.ip_file_path = None
                print("No valid IP file path found in settings")
        else:
            # First run - start with empty settings
            self.api_user = ""
            self.api_pass = ""
            self.snmp_comm = "public"
            self.ip_file_path = None
            print("First run - using empty settings")
    
    def handle_startup(self):
        """Handle application startup behavior"""
        if os.path.exists(SETTINGS_PATH):
            # On subsequent runs, check if we have a valid IP file
            if self.ip_file_path and os.path.exists(self.ip_file_path):
                print("Found cached IP file, starting refresh...")
                self.status_var.set(f"Loading data from: {os.path.basename(self.ip_file_path)}")
                # Start refresh with a small delay to let GUI initialize
                self.root.after(500, self.refresh_data)
            else:
                print("No valid IP file found in settings")
                self.status_var.set("Click Open to choose IP file.")
        else:
            # First run
            print("First run detected")
            self.status_var.set("Welcome! Click Open to choose IP file.")
    
    def _load_settings(self):
        """Load all settings (IP file path and credentials) from JSON, create file if missing"""
        if not os.path.exists(SETTINGS_PATH):
            # Create default settings file
            default = {"last_ip_file": None, "api_user": "", "api_pass": "", "snmp_comm": "public"}
            try:
                with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
                    json.dump(default, f, ensure_ascii=False, indent=2)
            except Exception:
                pass
            return default
        try:
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Ensure all expected keys exist
            return {
                "last_ip_file": data.get("last_ip_file", None),
                "api_user": data.get("api_user", ""),
                "api_pass": data.get("api_pass", ""),
                "snmp_comm": data.get("snmp_comm", "public")
            }
        except Exception:
            return {"last_ip_file": None, "api_user": "", "api_pass": "", "snmp_comm": "public"}

    def _save_settings(self):
        """Save all settings (IP file path and credentials) to JSON"""
        # Load existing settings first
        current_settings = self._load_settings()
        
        # Only update values that are actually set
        if self.ip_file_path:
            current_settings["last_ip_file"] = self.ip_file_path
        if self.api_user and self.api_pass:  # Only save API creds if both are set
            current_settings["api_user"] = self.api_user
            current_settings["api_pass"] = self.api_pass
        if self.snmp_comm:  # Always save SNMP community as it has a default
            current_settings["snmp_comm"] = self.snmp_comm
            
        try:
            with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
                json.dump(current_settings, f, ensure_ascii=False, indent=2)
        except Exception:
            pass


    def create_status_icons(self, size=22):
        """Create icons for different status types"""
        icons = {}
        
        # Online icon (green circle with checkmark)
        img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        # Green circle
        draw.ellipse([0, 0, size, size], fill=(0, 180, 0), outline=(0, 120, 0), width=1)
        # Add white checkmark
        if size >= 16:  # Only add details if icon is large enough
            check_points = [(size//4, size//2), (size//2-2, size*3//4), (size*3//4, size//4)]
            draw.line(check_points, fill=(255, 255, 255), width=2)
        icons["Online"] = ImageTk.PhotoImage(img)
        
        # Offline icon - ON state (bright red circle with X)
        img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        # Bright red circle
        draw.ellipse([0, 0, size, size], fill=(220, 0, 0), outline=(120, 0, 0), width=1)
        # Add white X
        if size >= 16:
            draw.line([(size//4, size//4), (size*3//4, size*3//4)], fill=(255, 255, 255), width=2)
            draw.line([(size*3//4, size//4), (size//4, size*3//4)], fill=(255, 255, 255), width=2)
        icons["Offline_on"] = ImageTk.PhotoImage(img)
        
        # Offline icon - OFF state (dimmed red circle with X)
        img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        # Dimmed red circle
        draw.ellipse([0, 0, size, size], fill=(140, 0, 0), outline=(120, 0, 0), width=1)
        # Add white X (slightly dimmed)
        if size >= 16:
            draw.line([(size//4, size//4), (size*3//4, size*3//4)], fill=(220, 220, 220), width=2)
            draw.line([(size*3//4, size//4), (size//4, size*3//4)], fill=(220, 220, 220), width=2)
        icons["Offline_off"] = ImageTk.PhotoImage(img)
        
        # For backward compatibility, keep the non-blinking version
        icons["Offline"] = icons["Offline_on"]
        
        # Failed icon (yellow triangle with !)
        img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        # Yellow triangle
        draw.polygon([(size//2, 0), (size, size-1), (0, size-1)], 
                    fill=(240, 180, 0), outline=(180, 140, 0), width=1)
        # Add exclamation mark
        if size >= 16:
            # Vertical line
            draw.line([(size//2, size//5), (size//2, size*2//3)], fill=(0, 0, 0), width=2)
            # Dot
            draw.ellipse([(size//2-1, size*3//4-1), (size//2+1, size*3//4+1)], fill=(0, 0, 0))
        icons["Failed"] = ImageTk.PhotoImage(img)
        
        # Off-On icon - ON state (orange pulsing circle)
        img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        # Bright orange circle
        draw.ellipse([0, 0, size, size], fill=(255, 140, 0), outline=(200, 100, 0), width=1)
        # Add up arrow
        if size >= 16:
            arrow_points = [(size//2, size//4), (size//4, size//2), (size*3//8, size//2),
                           (size*3//8, size*3//4), (size*5//8, size*3//4), 
                           (size*5//8, size//2), (size*3/4, size//2)]
            draw.polygon(arrow_points, fill=(255, 255, 255))
        icons["Off-On_on"] = ImageTk.PhotoImage(img)
        
        # Off-On icon - OFF state (dimmed orange circle)
        img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        # Dimmed orange circle
        draw.ellipse([0, 0, size, size], fill=(180, 100, 0), outline=(200, 100, 0), width=1)
        # Add faded up arrow
        if size >= 16:
            arrow_points = [(size//2, size//4), (size//4, size//2), (size*3//8, size//2),
                           (size*3//8, size*3//4), (size*5//8, size*3//4), 
                           (size*5//8, size//2), (size*3/4, size//2)]
            draw.polygon(arrow_points, fill=(200, 200, 200))
        icons["Off-On_off"] = ImageTk.PhotoImage(img)
        
        # Polling icon - ON state (blue pulsing circle with hourglass)
        img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        # Bright blue circle
        draw.ellipse([0, 0, size, size], fill=(150, 150, 150), outline=(120, 120, 120), width=1)
        # Add hourglass symbol
        if size >= 16:
            # Hourglass outline
            draw.polygon([(size//3, size//3), (size*2//3, size//3), (size*2//3, size*2//3), 
                          (size//3, size*2//3)], outline=(255, 255, 255), width=1)
            # Center line
            draw.line([(size//3, size//2), (size*2//3, size//2)], fill=(255, 255, 255), width=1)
        icons["Polling_on"] = ImageTk.PhotoImage(img)
        
        # Polling icon - OFF state (dimmed blue circle with hourglass)
        img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        # Dimmed blue circle
        draw.ellipse([0, 0, size, size], fill=(100, 100, 100), outline=(100, 100, 100), width=1)
        # Add hourglass symbol (dimmed)
        if size >= 16:
            # Hourglass outline
            draw.polygon([(size//3, size//3), (size*2//3, size//3), (size*2//3, size*2//3), 
                          (size//3, size*2//3)], outline=(200, 200, 200), width=1)
            # Center line
            draw.line([(size//3, size//2), (size*2//3, size//2)], fill=(200, 200, 200), width=1)
        icons["Polling_off"] = ImageTk.PhotoImage(img)
        
        return icons
    
    def toggle_blink(self):
        """Toggle the blink state for blinking items"""
        self.blink_state = not self.blink_state
        self.update_blinking_items()
        # Schedule next blink after 750ms for smoother blinking
        self.blink_timer = self.root.after(750, self.toggle_blink)
    
    def update_blinking_items(self):
        """Update any UI elements that need to blink"""
        try:
            for item_id in self.tree.get_children():
                tags = self.tree.item(item_id, 'tags')
                if not tags or 'blink' not in tags:
                    continue
                
                values = self.tree.item(item_id)['values']
                if not values:
                    continue
                    
                status = values[0]  # Status is in first column
                
                # Handle blinking based on status
                if status == "Off-On":
                    icon_state = "Off-On_on" if self.blink_state else "Off-On_off"
                elif status == "Offline":
                    icon_state = "Offline_on" if self.blink_state else "Offline_off"
                elif status == "Polling":
                    icon_state = "Polling_on" if self.blink_state else "Polling_off"
                else:
                    continue
                    
                # Update the icon and any cell colors that need updating
                self.tree.item(item_id, image=self.icons[icon_state])
                self.update_cell_colors(item_id, values)
        except Exception as e:
            print(f"Error in update_blinking_items: {str(e)}")
            if hasattr(e, '__traceback__'):
                import traceback
                traceback.print_exc()
    
    def open_ip_file(self):
        """Open file dialog to select an IP file"""
        try:
            print("Opening file dialog to select IP file...")
            file_path = filedialog.askopenfilename(
                title="Select IP File",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            
            if file_path:
                print(f"Selected file: {file_path}")
                # Verify file exists and is readable
                if not os.path.exists(file_path):
                    print(f"Error: File {file_path} does not exist")
                    messagebox.showerror("Error", f"File {file_path} does not exist")
                    return
                    
                try:
                    # Try to read the file to verify it's accessible
                    with open(file_path, "r", encoding="utf-8") as f:
                        first_line = f.readline().strip()
                        print(f"First line of file: {first_line}")
                except Exception as e:
                    print(f"Error reading file: {str(e)}")
                    messagebox.showerror("Error", f"Could not read file: {str(e)}")
                    return
                
                # Clear existing devices
                for row in self.tree.get_children():
                    self.tree.delete(row)
                
                self.ip_file_path = file_path
                self._save_settings()  # Save all settings
                print("Settings saved successfully")
                self.status_var.set(f"Loaded IP file: {os.path.basename(self.ip_file_path)}")
                self.refresh_data()
            else:
                print("No file selected")
        except Exception as e:
            print(f"Error in open_ip_file: {str(e)}")
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

    def open_settings(self):
        """Open the settings dialog and update credentials only if user chooses to change them"""
        dialog = SettingsDialog(self.root, self.api_user, self.api_pass, self.snmp_comm)
        if dialog.result:
            # Only update if user changed something
            changed = False
            if dialog.result["api_user"] != self.api_user:
                self.api_user = dialog.result["api_user"]
                changed = True
            if dialog.result["api_pass"] != self.api_pass:
                self.api_pass = dialog.result["api_pass"]
                changed = True
            if dialog.result["snmp_comm"] != self.snmp_comm:
                self.snmp_comm = dialog.result["snmp_comm"]
                changed = True
            if changed:
                self._save_settings()  # Save all settings
                self.status_var.set("Settings updated.")
                if self.ip_file_path:
                    self.refresh_data()

    def refresh_data(self):
        """Refresh the device data"""
        # Only check for IP file
        if not self.ip_file_path or not os.path.exists(self.ip_file_path):
            messagebox.showwarning("IP File", "Please click 'Open' and select an IP file first.")
            self.status_var.set("Click Open to choose IP file.")
            return
            
        # Save current settings
        self._save_settings()
        
        # Disable refresh button and update status
        self.refresh_btn.config(state=tk.DISABLED)
        self.status_var.set(f"Reading IP file: {os.path.basename(self.ip_file_path)}...")
        self.root.update_idletasks()
        
        # Read IPs in a separate thread to keep UI responsive
        def read_ips_thread():
            try:
                ips = read_ips(self.ip_file_path)
                if not ips:
                    self.root.after(0, lambda: self._handle_empty_ips())
                    return
                self.root.after(0, lambda: self._start_polling(ips))
            except Exception as e:
                self.root.after(0, lambda: self._handle_read_error(str(e)))
        
        thread = threading.Thread(target=read_ips_thread)
        thread.daemon = True
        thread.start()
    
    def _handle_empty_ips(self):
        """Handle case when no IPs are found"""
        messagebox.showinfo("No IPs", f"No IP addresses found in {os.path.basename(self.ip_file_path)}")
        self.status_var.set("Ready")
        self.refresh_btn.config(state=tk.NORMAL)
    
    def _handle_read_error(self, error_msg):
        """Handle IP file read error"""
        messagebox.showerror("Error", f"Failed to read {os.path.basename(self.ip_file_path)}: {error_msg}")
        self.status_var.set("Ready")
        self.refresh_btn.config(state=tk.NORMAL)
    
    def _start_polling(self, ips):
        """Start polling the devices"""
        is_first_run = len(self.tree.get_children()) == 0
        
        # Update refresh time
        refresh_time = time.strftime("%Y-%m-%d %H:%M:%S")
        self.refresh_var.set(f"Last refresh: {refresh_time}")
        
        # Reset polling state
        self.results_queue = []
        self.batch_timer = None
        self.total_ips = len(ips)
        self.completed_ips = 0
        
        if is_first_run:
            # First run - show polling status
            for ip in sorted(ips, key=lambda x: ip_address(x)):
                device = {
                    "ip": ip,
                    "status": "Polling",
                    "cpu": "...", "mem": "...", "uptime": "...",
                    "vendor": "...", "model": "...", "serial": "..."
                }
                self._insert_or_update_device_row(device)
            self.status_var.set("Initializing first scan...")
        
        # Start polling thread
        def poll_thread():
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                # Submit all tasks
                futures = {}
                for ip in ips:
                    if self.is_shutting_down:
                        break
                    futures[executor.submit(collect, ip, self.api_user, self.api_pass, self.snmp_comm)] = ip
                
                # Process completed futures
                try:
                    for future in as_completed(futures):
                        if self.is_shutting_down:
                            executor.shutdown(wait=False)  # Stop accepting new tasks
                            break
                            
                        ip = futures[future]
                        try:
                            result = future.result()
                            if result is None:  # Handle None result
                                result = {
                                    "ip": ip,
                                    "status": "Failed",
                                    "cpu": "N/A", "mem": "N/A", "uptime": "N/A",
                                    "vendor": "N/A", "model": "N/A", "serial": "N/A"
                                }
                        except Exception as e:
                            print(f"Error polling {ip}: {str(e)}")
                            result = {
                                "ip": ip,
                                "status": "Failed",
                                "cpu": "N/A", "mem": "N/A", "uptime": "N/A",
                                "vendor": "N/A", "model": "N/A", "serial": "N/A"
                            }
                        
                        if not self.is_shutting_down:
                            self.results_queue.append(result)
                            self.completed_ips += 1
                            # Update status
                            self.root.after(0, lambda: self.status_var.set(
                                f"Polled {self.completed_ips}/{self.total_ips} devices..."
                            ))
                except Exception as e:
                    print(f"Error during polling: {str(e)}")
                
            # Signal completion if not shutting down
            if not self.is_shutting_down:
                self.root.after(0, self._finish_polling)
        
        # Start batch updates
        def update_batch():
            try:
                # Process up to 5 results at a time
                for _ in range(5):
                    if self.results_queue:
                        device = self.results_queue.pop(0)
                        self._insert_or_update_device_row(device)
                
                # Schedule next batch if there are more results or polling isn't finished
                if self.results_queue or self.completed_ips < self.total_ips:
                    self.batch_timer = self.root.after(100, update_batch)
                else:
                    self.batch_timer = None
            except Exception as e:
                print(f"Error in batch update: {str(e)}")
                self.batch_timer = self.root.after(100, update_batch)
                
        # Start batch updates
        self.batch_timer = self.root.after(100, update_batch)
        
        # Start polling thread
        self.status_var.set(f"Starting to poll {len(ips)} devices...")
        
        # Start polling thread
        self.status_var.set(f"Polling {len(ips)} devices...")
        if self.refresh_thread and self.refresh_thread.is_alive():
            # If there's an existing thread, we'll let it finish
            print("Previous refresh still running...")
            return
            
        self.refresh_thread = threading.Thread(target=poll_thread)
        self.refresh_thread.daemon = True
        self.refresh_thread.start()
    #    print("Started polling thread...")
    def _finish_polling(self):
        """Called when polling is complete"""
        try:
            # Process any remaining results
            while self.results_queue:
                device = self.results_queue.pop(0)
                self._insert_or_update_device_row(device)
            
            # Get current devices from tree
            devices = []
            for item_id in self.tree.get_children():
                values = self.tree.item(item_id)['values']
                devices.append({
                    "ip": values[1],  # IP is in second column
                    "status": norm_status(values[0])  # Status is in first column
                })
                
            # Calculate totals using normalized statuses
            t = len(devices)
            # Count online devices (including Failed ones since they're pingable)
            o = sum(1 for d in devices if d["status"] in ["Online", "Failed"])
            # Keep track of failed count separately (but don't add to total)
            f = sum(1 for d in devices if d["status"] == "Failed")
            # Only devices marked as Offline count towards offline total
            off = sum(1 for d in devices if d["status"] == "Offline")
            p = sum(1 for d in devices if d["status"] == "Polling")
            
            # Handle any remaining polling devices
            if p > 0:
                # Update both the internal list and the tree view
                for item_id in self.tree.get_children():
                    if self.tree.item(item_id)['values'][0] == "Polling":
                        # Update tree view
                        values = list(self.tree.item(item_id)['values'])
                        values[0] = "Failed"
                        self.tree.item(item_id, values=values)
                        # Update our device list
                        for d in devices:
                            if d["ip"] == values[1]:
                                d["status"] = "Failed"
                
                # Recount after converting polling to failed
                # Failed devices are now counted as part of online
                o = sum(1 for d in devices if d["status"] in ["Online", "Failed"])
                f = sum(1 for d in devices if d["status"] == "Failed")
                p = 0
            
            # Update the individual counters
            self.total_var.set(str(t))
            self.online_var.set(str(o))
            self.failed_var.set(str(f))
            self.offline_var.set(str(off))
            self.status_var.set(f"✨ Ready. {t} devices processed.")
            self.refresh_btn.config(state=tk.NORMAL)
            
            # Clean up timers
            if self.batch_timer:
                self.root.after_cancel(self.batch_timer)
                self.batch_timer = None
                
            if self.refresh_timer:
                self.root.after_cancel(self.refresh_timer)
            self.refresh_timer = self.root.after(int(REFRESH_SEC * 1000), self.refresh_data)
            
            
            
        except Exception as e:
            print(f"Error in _finish_polling: {str(e)}")
            self.status_var.set("Error during polling completion. Check console for details.")
            self.refresh_btn.config(state=tk.NORMAL)
    
    def _insert_or_update_device_row(self, device):
        """Insert or update a device row in the treeview"""
        ip = device["ip"]
        # Normalize the status here
        status = norm_status(device["status"])
        
        # Get CPU and Memory values first
        cpu_val = device["cpu"]
        mem_val = device["mem"]
        
        # Prepare values for display
        values = [
            status,  # Column 0: Status text
            ip,      # Column 1: IP
            device.get("hostname", "N/A"),  # Column 2: Hostname from SNMP
            device["vendor"],    # Column 3: Vendor
            device["model"],     # Column 4: Model
            device["serial"],    # Column 5: Serial
            cpu_val,            # Column 6: CPU
            mem_val,            # Column 7: Memory
            device["uptime"]     # Column 8: Uptime
        ]
        
        # Get initial icon state based on status
        if status == "Offline":
            icon_state = "Offline_on"
        elif status == "Online":
            icon_state = "Online"
        elif status == "Failed":
            icon_state = "Failed"
        elif status == "Off-On":
            icon_state = "Off-On_on"
        else:
            icon_state = "Polling_on"
            
        # Function to get color tags for CPU/Memory values
        def get_value_tags(value, prefix, column):
            try:
                if value == "N/A" or value == "..." or not value:
                    return []
                    
                # Clean and convert the value
                cleaned_value = str(value).strip().replace("%", "")
                if not cleaned_value:
                    return []
                    
                val = float(cleaned_value)
                if val >= 30:  # Red threshold
                    return [f"{prefix}_red_{column}"]
                elif val >= 20:  # Orange threshold
                    return [f"{prefix}_orange_{column}"]
                return []
            except (ValueError, TypeError):
                return []
        
        # Find existing item
        item = None
        for child in self.tree.get_children():
            if self.tree.item(child)["values"][1] == ip:  # Check IP column
                item = child
                break
        
        # Get initial icon state based on status
        if status == "Offline":
            icon_state = "Offline_on" if self.blink_state else "Offline_off"
        elif status == "Off-On":
            icon_state = "Off-On_on" if self.blink_state else "Off-On_off"
        elif status == "Polling":
            icon_state = "Polling_on" if self.blink_state else "Polling_off"
        else:
            icon_state = status
        
        # Set blinking tag if needed
        tags = ["blink"] if status in ["Offline", "Off-On", "Polling"] else []
        
        # Insert or update the row
        if item:
            self.tree.item(item, values=values, image=self.icons[icon_state], tags=tuple(tags))
            # Apply color to any CPU/Memory warnings
            self.update_cell_colors(item, values)
        else:
            item = self.tree.insert("", tk.END, values=values, image=self.icons[icon_state], tags=tuple(tags))
            self.update_cell_colors(item, values)
    
    def export_to_csv(self):
        """Export the current view to CSV"""
        if not self.tree.get_children():
            messagebox.showwarning("Export", "No data to export.")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Export to CSV"
        )
        if not file_path:
            return
            
        try:
            with open(file_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                # Write headers (skip icon column)
                writer.writerow([col["text"] for col in COLUMNS[1:]])
                # Write data
                for item_id in self.tree.get_children():
                    writer.writerow(self.tree.item(item_id)["values"])
            self.status_var.set(f"Exported data to {os.path.basename(file_path)}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export: {str(e)}")
    
    def update_cell_colors(self, item, values):
        """Update cell colors for CPU and Memory values"""
        try:
            # CPU value is at index 6
            cpu_val = values[6]
            if isinstance(cpu_val, str) and cpu_val not in ("N/A", "..."):
                try:
                    cpu_num = float(cpu_val.replace("%", ""))
                    if cpu_num >= 80:
                        self._set_cell_color(item, 6, self.threshold_colors["red"])
                    elif cpu_num >= 60:
                        self._set_cell_color(item, 6, self.threshold_colors["orange"])
                except ValueError:
                    pass
            
            # Memory value is at index 7
            mem_val = values[7]
            if isinstance(mem_val, str) and mem_val not in ("N/A", "..."):
                try:
                    mem_num = float(mem_val.replace("%", ""))
                    if mem_num >= 80:
                        self._set_cell_color(item, 7, self.threshold_colors["red"])
                    elif mem_num >= 60:
                        self._set_cell_color(item, 7, self.threshold_colors["orange"])
                except ValueError:
                    pass
        except Exception as e:
            print(f"Error updating cell colors: {e}")
    
    def sort_by_column(self, col_id):
        """Sort treeview by column when header is clicked"""
        if self.sort_column == col_id:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_reverse = False
            self.sort_column = col_id
            
        # Get all items
        items = [(self.tree.set(child, col_id), child) for child in self.tree.get_children("")]
        
        # Sort items
        items.sort(reverse=self.sort_reverse)
        
        # Move items in sorted order
        for index, (_, child) in enumerate(items):
            self.tree.move(child, "", index)
    
    def on_closing(self):
        """Handle application shutdown"""
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            print("Shutting down...")
            self.is_shutting_down = True  # Set shutdown flag
            
            # Cancel all timers
            if self.refresh_timer:
                self.root.after_cancel(self.refresh_timer)
            if self.batch_timer:
                self.root.after_cancel(self.batch_timer)
            if self.blink_timer:
                self.root.after_cancel(self.blink_timer)
            
            # Clear the results queue
            self.results_queue.clear()
            
            # Wait for polling thread to finish (with timeout)
            if self.refresh_thread and self.refresh_thread.is_alive():
                print("Waiting for polling to complete...")
                self.refresh_thread.join(timeout=2.0)  # Wait up to 2 seconds
            
            print("Cleanup complete")
            self.root.destroy()

# Define main function for entry point
def main():
    # Test SNMP configuration
    print("Testing SNMP configuration...")
    try:
        # Create a test ObjectIdentity to verify SNMP setup
        test_oid = ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)
        print("SNMP configuration OK")
    except Exception as e:
        print(f"SNMP configuration error: {str(e)}")
        print("You might need to install SNMP MIBs. Try:")
        print("pip install pysnmp-mibs")
        print("Continuing anyway as some basic OIDs might still work...")
    
    try:
        root = tk.Tk()
        app = NmsApp(root)
        root.mainloop()
    except Exception as e:
        print(f"Error starting application: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

# Start the application
if __name__ == "__main__":
    main()