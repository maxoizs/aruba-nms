#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nms_gui.py - GUI version of NMS Live Monitor
- Tkinter-based UI with scrollable table
- Clean refresh without flicker
- Color indicators for status
- Status icons with blinking for transitional states
- Live updates with periodic refresh
"""

import os, sys, re, time
from ipaddress import ip_address
from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, Canvas
import base64, io
from PIL import Image, ImageTk, ImageDraw  # For icon creation
import requests, urllib3
from ping3 import ping
from pysnmp.hlapi import *

urllib3.disable_warnings()

# ---------------- Configuration ----------------
REFRESH_SEC = 60.0
MAX_WORKERS = 20
IP_FILE = "ip.txt"

# Column definitions
COLUMNS = [
    {"id": "icon", "text": "", "width": 30},  # New icon column
    {"id": "ip", "text": "IP Address", "width": 120},
    {"id": "status", "text": "Status", "width": 80},
    {"id": "vendor", "text": "Vendor", "width": 100},
    {"id": "model", "text": "Model", "width": 140},
    {"id": "serial", "text": "Serial", "width": 120},
    {"id": "cpu", "text": "CPU %", "width": 60},
    {"id": "mem", "text": "Mem %", "width": 60},
    {"id": "uptime", "text": "Uptime", "width": 100}
]

# Status definitions with icons
STATUS_TYPES = {
    "Online": {"color": "#e0ffe0", "blink": False},
    "Offline": {"color": "#ffe0e0", "blink": True},  # Now Offline will blink too
    "Failed": {"color": "#fff0c0", "blink": False},
    "Off-On": {"color": "#ffffc0", "blink": True},  # Transitional state that blinks
    "Polling": {"color": "#e0e0ff", "blink": True}  # Polling status that blinks
}

# ---------------- SNMP helpers ----------------
def snmp_get(ip, comm, oid, timeout=1, retries=1):
    try:
        errorIndication, errorStatus, errorIndex, varBinds = next(
            getCmd(SnmpEngine(), CommunityData(comm, mpModel=1),
                  UdpTransportTarget((ip,161),timeout=timeout,retries=retries),
                  ContextData(), ObjectType(ObjectIdentity(oid)))
        )
        if errorIndication or errorStatus:
            return None
        for varBind in varBinds:
            val = varBind[1].prettyPrint()
            if "No Such" in val:
                return None
            return val
    except Exception:
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
    sess=requests.Session(); sess.verify=False
    base=login=ver=None
    for v in ["10.12","10.08","10.04"]:
        b=f"https://{ip}/rest/v{v}"
        lr=api_login(sess,b,u,p)
        if lr: base=b; login=lr; ver=v; break
    if not base: return None
    csrf=login.headers.get("X-CSRF-TOKEN")
    if csrf: sess.headers.update({"X-CSRF-TOKEN":csrf})

    sysinfo=_get(sess,base,"/system?attributes=product_info,hostname,platform_name,platform_os_version")
    product=sysinfo.get("product_info") if sysinfo else None
    serial=model="N/A"
    if product:
        serial=product.get("serial_number","N/A")
        model=sysinfo.get("platform_name","N/A")
    elif sysinfo:
        model=sysinfo.get("platform_name","N/A"); serial=sysinfo.get("system_mac","N/A")

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
    return {"vendor":"Aruba CX","model":model,"serial":serial,"uptime":uptime,"cpu":cpu,"memory":mem}

# ---------------- SNMP fallback ----------------
def snmp_data(ip,comm):
    descr=snmp_get(ip,comm,"1.3.6.1.2.1.1.1.0")
    if not descr: return None
    return {
        "vendor":detect_vendor(descr),
        "model":model_from_descr(descr),
        "serial":"N/A",
        "uptime":snmp_get(ip,comm,"1.3.6.1.2.1.1.3.0") or "N/A",
        "cpu":"N/A","memory":"N/A"
    }

# ---------------- Status handling ----------------
def norm_status(s):
    if not s: return "Failed"
    s=s.strip().lower()
    if s.startswith("on"): return "Online"
    if s.startswith("off"):
        if "on" in s: return "Off-On"  # Transitional state
        return "Offline"
    if s.startswith("fail"): return "Failed"
    if s.startswith("poll"): return "Polling"
    return "Failed"

# ---------------- Device worker ----------------
def collect(ip,u,p,comm)->Dict[str,Any]:
    try: rtt=ping(ip,timeout=1)
    except Exception: rtt=None
    
    # Check for previously known device to detect state transitions
    last_status = None
    
    if rtt is None:
        status = "Offline"
        # You could add logic here to detect Off-On transitions if needed
        # For example, if device was previously online, set status to "Off-On"
        
        return {"ip":ip,"status":status,"cpu":"N/A","mem":"N/A","uptime":"N/A",
                "vendor":"N/A","model":"N/A","serial":"N/A"}
                
    d=aruba_api(ip,u,p)
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
                
        return {"ip":ip,"status":"Online","cpu":d.get("cpu","N/A"),"mem":d.get("memory","N/A"),
                "uptime":d.get("uptime","N/A"),"vendor":d.get("vendor","N/A"),
                "model":d.get("model","N/A"),"serial":d.get("serial","N/A")}
                
    d=snmp_data(ip,comm)
    if d:
        return {"ip":ip,"status":"Online","cpu":d.get("cpu","N/A"),"mem":d.get("memory","N/A"),
                "uptime":d.get("uptime","N/A"),"vendor":d.get("vendor","N/A"),
                "model":d.get("model","N/A"),"serial":d.get("serial","N/A")}
                
    return {"ip":ip,"status":"Failed","cpu":"N/A","mem":"N/A","uptime":"N/A",
            "vendor":"N/A","model":"N/A","serial":"N/A"}

# ---------------- Polling ----------------
def read_ips():
    with open(IP_FILE,"r",encoding="utf-8") as f:
        ips=[ln.strip() for ln in f if ln.strip()]
    return sorted(ips,key=lambda x: ip_address(x))

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
    for d in devs: d["status"]=norm_status(d.get("status",""))
    # Default sorting order (can be overridden by column sorting)
    order={"Polling": 0, "Offline":1, "Failed":2, "Online":3, "Off-On":4}
    return sorted(devs,key=lambda d:(order.get(d["status"],5), ip_address(d["ip"])))

def counts(devs):
    t=len(devs)
    o=sum(1 for d in devs if norm_status(d["status"])=="Online")
    f=sum(1 for d in devs if norm_status(d["status"])=="Failed")
    off=sum(1 for d in devs if norm_status(d["status"])=="Offline")
    p=sum(1 for d in devs if norm_status(d["status"])=="Polling")
    return t,o,f,off,p

# ---------------- GUI Application ----------------
class NmsApp:
    def __init__(self, root):
        self.root = root
        root.title("Aruba NMS Live Monitor")
        root.geometry("900x600")
        
        self.api_user = ""
        self.api_pass = ""
        self.snmp_comm = "public"
        self.devices = []
        self.previous_states = {}  # Store previous device states
        self.refresh_timer = None
        self.blink_timer = None
        self.blink_state = False  # For blinking icons
        
        # Variables for tracking sorting
        self.sort_column = "ip"  # Default sort column
        self.sort_reverse = False  # Default sort direction (ascending)
        
        # Create status icons
        self.icons = self.create_status_icons()
        
        # Create the main frame
        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create summary frame at the top
        self.summary_frame = ttk.Frame(self.main_frame)
        self.summary_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Summary labels
        self.summary_var = tk.StringVar(value="Summary: No devices")
        self.summary_label = ttk.Label(self.summary_frame, textvariable=self.summary_var, font=("Helvetica", 10, "bold"))
        self.summary_label.pack(side=tk.LEFT)
        
        self.refresh_var = tk.StringVar(value="Last refresh: —")
        self.refresh_label = ttk.Label(self.summary_frame, textvariable=self.refresh_var)
        self.refresh_label.pack(side=tk.RIGHT)
        
        # Create control frame below summary
        self.control_frame = ttk.Frame(self.main_frame)
        self.control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Add refresh button
        self.refresh_btn = ttk.Button(self.control_frame, text="Refresh Now", command=self.refresh_data)
        self.refresh_btn.pack(side=tk.RIGHT, padx=5)
        
        # Add settings button
        self.settings_btn = ttk.Button(self.control_frame, text="Settings", command=self.open_settings)
        self.settings_btn.pack(side=tk.RIGHT, padx=5)
        
        # Create Treeview for data display with scrollbar
        self.tree_frame = ttk.Frame(self.main_frame)
        self.tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add vertical scrollbar
        self.scrollbar = ttk.Scrollbar(self.tree_frame)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Create Treeview
        self.tree = ttk.Treeview(self.tree_frame, yscrollcommand=self.scrollbar.set, selectmode='browse')
        self.scrollbar.config(command=self.tree.yview)
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        # Define columns - use #0 for icon and columns for data
        column_ids = [col["id"] for col in COLUMNS[1:]]  # Skip the icon column
        self.tree['columns'] = column_ids
        self.tree.column('#0', width=40, stretch=tk.NO, anchor=tk.CENTER)  # Use column #0 for icons with proper centering
        self.tree.heading('#0', text='')
        
        # Set column headings and widths
        for col in COLUMNS[1:]:  # Skip icon column
            self.tree.column(col["id"], width=col["width"], anchor=tk.W)
            # Bind the heading click to sort method with a lambda that passes the column ID
            self.tree.heading(col["id"], text=col["text"], anchor=tk.W, 
                             command=lambda col_id=col["id"]: self.sort_by_column(col_id))
            
        # Style configuration for proper padding and alignment
        style = ttk.Style()
        style.configure("Treeview", rowheight=24)  # Increase row height for better icon display
        
        # Status bar at the bottom
        self.status_var = tk.StringVar(value="Ready")
        self.status_bar = ttk.Label(self.main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(fill=tk.X, padx=5, pady=2)
        
        # Show login dialog at startup
        self.root.after(100, self.open_settings)
        
        # Start blinking timer
        self.toggle_blink()
    
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
                           (size*5//8, size//2), (size*3//4, size//2)]
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
                           (size*5//8, size//2), (size*3//4, size//2)]
            draw.polygon(arrow_points, fill=(200, 200, 200))
        icons["Off-On_off"] = ImageTk.PhotoImage(img)
        
        # Polling icon - ON state (blue pulsing circle with hourglass)
        img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        # Bright blue circle
        draw.ellipse([0, 0, size, size], fill=(80, 80, 240), outline=(60, 60, 180), width=1)
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
        draw.ellipse([0, 0, size, size], fill=(60, 60, 180), outline=(60, 60, 180), width=1)
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
        # Schedule next blink after 500ms
        self.blink_timer = self.root.after(500, self.toggle_blink)
    
    def update_blinking_items(self):
        """Update any UI elements that need to blink"""
        for item_id in self.tree.get_children():
            tags = self.tree.item(item_id, 'tags')
            if 'blink' in tags:
                status_col = self.tree.item(item_id, 'values')[1]  # Get status value (index 1 now)
                
                # Handle Off-On blinking
                if status_col == "Off-On":
                    icon_state = "Off-On_on" if self.blink_state else "Off-On_off"
                    # Update the icon in column #0
                    self.tree.item(item_id, image=self.icons[icon_state])
                
                # Handle Offline blinking
                elif status_col == "Offline":
                    icon_state = "Offline_on" if self.blink_state else "Offline_off"
                    # Update the icon in column #0
                    self.tree.item(item_id, image=self.icons[icon_state])

    def open_settings(self):
        """Open settings dialog to set credentials"""
        dialog = SettingsDialog(self.root, self.api_user, self.api_pass, self.snmp_comm)
        if dialog.result:
            self.api_user = dialog.result.get("api_user", "")
            self.api_pass = dialog.result.get("api_pass", "")
            self.snmp_comm = dialog.result.get("snmp_comm", "public")
            if self.api_user and self.api_pass:
                self.refresh_data()

    def refresh_data(self):
        """Refresh the device data"""
        if not self.api_user or not self.api_pass:
            messagebox.showwarning("Missing Credentials", 
                                  "Please set your API username and password in Settings.")
            return
        
        self.status_var.set("Reading IP file...")
        self.root.update_idletasks()
        
        try:
            ips = read_ips()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read {IP_FILE}: {e}")
            self.status_var.set("Ready")
            return
        
        if not ips:
            messagebox.showinfo("No IPs", f"No IP addresses found in {IP_FILE}")
            self.status_var.set("Ready")
            return
        
        self.status_var.set(f"Preparing to poll {len(ips)} devices...")
        self.root.update_idletasks()
        
        # Start polling in a separate thread to keep UI responsive
        self.refresh_btn.config(state=tk.DISABLED)
        
        # Clear the current treeview to prepare for the new data
        for row in self.tree.get_children():
            self.tree.delete(row)
        
        # Update last refresh time
        refresh_time = time.strftime("%Y-%m-%d %H:%M:%S")
        self.refresh_var.set(f"Last refresh: {refresh_time}")
        
        def poll_thread():
            # Get generator that will yield results as they arrive
            result_generator = poll_all(ips, self.api_user, self.api_pass, self.snmp_comm, self.previous_states)
            
            # Start the async UI update process from the main thread
            self.root.after(0, lambda: self.async_update_ui(result_generator))
        
        import threading
        thread = threading.Thread(target=poll_thread)
        thread.daemon = True
        thread.start()

    def update_ui(self, devices):
        """Update the UI with all device data at once"""
        self.devices = sort_devs(devices)
        
        # Update previous states dictionary
        for device in devices:
            ip = device.get("ip")
            status = device.get("status")
            if ip and status:
                self.previous_states[ip] = status
        
        # Clear the treeview
        for row in self.tree.get_children():
            self.tree.delete(row)
        
        # Update summary
        t, o, f, off, p = counts(devices)
        self.summary_var.set(f"Summary: Total: {t} | Online: {o} | Failed: {f} | Offline: {off} | Polling: {p}")
        
        # Update last refresh time
        refresh_time = time.strftime("%Y-%m-%d %H:%M:%S")
        self.refresh_var.set(f"Last refresh: {refresh_time}")
        
        # Add device rows
        for device in self.devices:
            self._insert_or_update_device_row(device)
        
        # Configure colors for status tags
        for status_name, props in STATUS_TYPES.items():
            self.tree.tag_configure(status_name.lower(), background=props["color"])
        
        # Apply current sort settings
        if self.sort_column:
            self.sort_by_column(self.sort_column)
        
        self.status_var.set(f"Ready. {t} devices loaded.")
        self.refresh_btn.config(state=tk.NORMAL)
        
        # Set timer for next refresh
        if self.refresh_timer:
            self.root.after_cancel(self.refresh_timer)
        self.refresh_timer = self.root.after(int(REFRESH_SEC * 1000), self.refresh_data)
    
    def async_update_ui(self, result_generator):
        """Process device results asynchronously as they arrive"""
        # Dictionary to keep track of devices and their tree item IDs
        ip_to_item = {}
        polling_count = 0
        completed_count = 0
        total_count = 0
        
        def process_next_result():
            nonlocal polling_count, completed_count, total_count
            
            try:
                device = next(result_generator)
                
                # For first batch of results (IPs), just count them
                if device.get("status") == "Polling":
                    polling_count += 1
                    total_count += 1
                else:
                    # This is a real result, decrement polling count and increment completed
                    polling_count -= 1
                    completed_count += 1
                
                # Insert or update the device in the treeview
                item_id = ip_to_item.get(device.get("ip"))
                if item_id:
                    # Update existing row
                    self._update_device_row(item_id, device)
                else:
                    # Insert new row
                    item_id = self._insert_or_update_device_row(device)
                    ip_to_item[device.get("ip")] = item_id
                
                # Update status bar with progress
                self.status_var.set(
                    f"Polling devices... {completed_count}/{total_count} completed, {polling_count} pending"
                )
                
                # Schedule processing of next result
                self.root.after(10, process_next_result)
            
            except StopIteration:
                # All results processed
                # Update summary counts
                t = total_count
                o = sum(1 for d in self.tree.get_children() if self.tree.item(d, 'values')[1] == "Online")
                f = sum(1 for d in self.tree.get_children() if self.tree.item(d, 'values')[1] == "Failed")
                off = sum(1 for d in self.tree.get_children() if self.tree.item(d, 'values')[1] == "Offline")
                p = sum(1 for d in self.tree.get_children() if self.tree.item(d, 'values')[1] == "Polling")
                
                self.summary_var.set(f"Summary: Total: {t} | Online: {o} | Failed: {f} | Offline: {off} | Polling: {p}")
                
                # Apply current sort settings
                if self.sort_column:
                    self.sort_by_column(self.sort_column)
                
                self.status_var.set(f"Ready. {t} devices loaded.")
                self.refresh_btn.config(state=tk.NORMAL)
                
                # Set timer for next refresh
                if self.refresh_timer:
                    self.root.after_cancel(self.refresh_timer)
                self.refresh_timer = self.root.after(int(REFRESH_SEC * 1000), self.refresh_data)
        
        # Start the async processing
        process_next_result()
    
    def _insert_or_update_device_row(self, device):
        """Helper method to insert or update a device row in the treeview"""
        status = device.get("status", "")
        # Determine proper tags for styling
        tags = [status.lower()]
        
        # Add blink tag if this status should blink
        if status in STATUS_TYPES and STATUS_TYPES[status]["blink"]:
            tags.append("blink")
        
        # Prepare values for data columns (all except icon)
        values = []
        for col in COLUMNS[1:]:  # Skip icon column
            values.append(device.get(col["id"].lower(), "N/A"))
        
        # Get appropriate icon based on status
        icon = None
        if status == "Off-On":
            # For blinking status, start with 'on' state
            icon = self.icons["Off-On_on"]
        elif status == "Offline":
            # For offline status (which now blinks), start with 'on' state
            icon = self.icons["Offline_on"]
        elif status == "Polling":
            # For polling status (which blinks), start with 'on' state
            icon = self.icons["Polling_on"]
        elif status in self.icons:
            icon = self.icons[status]
        
        # Insert row with icon in column #0 and values in data columns
        item_id = self.tree.insert('', tk.END, text='', image=icon, values=values, tags=tuple(tags))
        return item_id
    
    def _update_device_row(self, item_id, device):
        """Helper method to update an existing device row in the treeview"""
        status = device.get("status", "")
        # Determine proper tags for styling
        tags = [status.lower()]
        
        # Add blink tag if this status should blink
        if status in STATUS_TYPES and STATUS_TYPES[status]["blink"]:
            tags.append("blink")
        
        # Prepare values for data columns (all except icon)
        values = []
        for col in COLUMNS[1:]:  # Skip icon column
            values.append(device.get(col["id"].lower(), "N/A"))
        
        # Get appropriate icon based on status
        icon = None
        if status == "Off-On":
            # For blinking status, start with 'on' state
            icon = self.icons["Off-On_on"]
        elif status == "Offline":
            # For offline status (which now blinks), start with 'on' state
            icon = self.icons["Offline_on"]
        elif status == "Polling":
            # For polling status (which blinks), start with 'on' state
            icon = self.icons["Polling_on"]
        elif status in self.icons:
            icon = self.icons[status]
            
        # Update the row with new values
        self.tree.item(item_id, image=icon, values=values, tags=tuple(tags))
    
    def sort_by_column(self, column_id):
        """Sort the treeview by the specified column"""
        # If clicking on the same column, toggle sort direction
        if self.sort_column == column_id:
            self.sort_reverse = not self.sort_reverse
        else:
            # Otherwise, sort by the new column in ascending order
            self.sort_column = column_id
            self.sort_reverse = False
        
        # Get all items from the treeview
        item_list = [(self.tree.set(item_id, column_id), item_id) for item_id in self.tree.get_children('')]
        
        # Apply special sorting rules for certain columns
        if column_id == "status":
            # For status column, sort by status priority
            status_order = {"Online": 0, "Off-On": 1, "Failed": 2, "Offline": 3, "Polling": 4}
            item_list = [(status_order.get(self.tree.set(item_id, column_id), 999), item_id) for item_id in self.tree.get_children('')]
        elif column_id == "ip":
            # For IP column, sort by IP address numerically
            try:
                item_list = [(ip_address(self.tree.set(item_id, column_id)), item_id) for item_id in self.tree.get_children('')]
            except:
                # If IP parsing fails, fall back to string sorting
                pass
        elif column_id in ["cpu", "mem"]:
            # For percentage columns, strip the % sign and sort numerically
            def extract_numeric(value):
                try:
                    # Remove % and convert to float
                    return float(value.replace('%', ''))
                except (ValueError, AttributeError):
                    return -1  # For "N/A" or other non-numeric values
            
            item_list = [(extract_numeric(self.tree.set(item_id, column_id)), item_id) for item_id in self.tree.get_children('')]
        
        # Sort the list
        item_list.sort(reverse=self.sort_reverse)
        
        # Rearrange items in the treeview according to the sort
        for index, (val, item_id) in enumerate(item_list):
            self.tree.move(item_id, '', index)
        
        # Update column headings to show sort indicators
        for col in COLUMNS[1:]:  # Skip icon column
            column_name = col["id"]
            heading_text = col["text"]
            
            # Add sort indicator to the sorted column
            if column_name == self.sort_column:
                indicator = " ▼" if self.sort_reverse else " ▲"
                self.tree.heading(column_name, text=f"{heading_text}{indicator}")
            else:
                self.tree.heading(column_name, text=heading_text)


class SettingsDialog:
    def __init__(self, parent, api_user, api_pass, snmp_comm):
        self.result = None
        
        # Create the dialog window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Connection Settings")
        self.dialog.transient(parent)
        self.dialog.resizable(False, False)
        
        # Make it modal
        self.dialog.grab_set()
        
        # Create form
        frame = ttk.Frame(self.dialog, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # API Username
        ttk.Label(frame, text="API Username:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.api_user_var = tk.StringVar(value=api_user)
        ttk.Entry(frame, width=30, textvariable=self.api_user_var).grid(row=0, column=1, pady=5, padx=5)
        
        # API Password
        ttk.Label(frame, text="API Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.api_pass_var = tk.StringVar(value=api_pass)
        ttk.Entry(frame, width=30, textvariable=self.api_pass_var, show="*").grid(row=1, column=1, pady=5, padx=5)
        
        # SNMP Community
        ttk.Label(frame, text="SNMP Community:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.snmp_comm_var = tk.StringVar(value=snmp_comm)
        ttk.Entry(frame, width=30, textvariable=self.snmp_comm_var).grid(row=2, column=1, pady=5, padx=5)
        
        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="OK", command=self.on_ok).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.dialog.destroy).pack(side=tk.LEFT, padx=5)
        
        # Center the dialog
        self.dialog.update_idletasks()
        width = self.dialog.winfo_width()
        height = self.dialog.winfo_height()
        x = (parent.winfo_width() - width) // 2 + parent.winfo_x()
        y = (parent.winfo_height() - height) // 2 + parent.winfo_y()
        self.dialog.geometry(f"+{x}+{y}")
        
        # Set focus to the first entry
        self.dialog.bind('<Return>', self.on_ok)
        
        # Wait for the dialog to close
        parent.wait_window(self.dialog)
    
    def on_ok(self, event=None):
        """Save settings and close the dialog"""
        self.result = {
            "api_user": self.api_user_var.get(),
            "api_pass": self.api_pass_var.get(),
            "snmp_comm": self.snmp_comm_var.get() or "public"
        }
        self.dialog.destroy()


if __name__ == "__main__":
    # Create sample IP file if it doesn't exist
    if not os.path.exists(IP_FILE):
        with open(IP_FILE, "w") as f:
            f.write("192.168.1.1\n")
            f.write("192.168.1.2\n")
            f.write("10.0.0.1\n")
        
    root = tk.Tk()
    app = NmsApp(root)
    root.mainloop()