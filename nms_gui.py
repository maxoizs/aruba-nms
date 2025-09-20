#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nms_gui.py - GUI version of NMS Live Monitor
- Tkinter-based UI with scrollable table
- Clean refresh without flicker
- Color indicators for status
- Live updates with periodic refresh
"""

import os, sys, re, time
from ipaddress import ip_address
from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
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
    {"id": "ip", "text": "IP Address", "width": 120},
    {"id": "status", "text": "Status", "width": 80},
    {"id": "vendor", "text": "Vendor", "width": 100},
    {"id": "model", "text": "Model", "width": 140},
    {"id": "serial", "text": "Serial", "width": 120},
    {"id": "cpu", "text": "CPU %", "width": 60},
    {"id": "mem", "text": "Mem %", "width": 60},
    {"id": "uptime", "text": "Uptime", "width": 100}
]

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
    if s.startswith("off"): return "Offline"
    if s.startswith("fail"): return "Failed"
    return "Failed"

# ---------------- Device worker ----------------
def collect(ip,u,p,comm)->Dict[str,Any]:
    try: rtt=ping(ip,timeout=1)
    except Exception: rtt=None
    if rtt is None:
        return {"ip":ip,"status":"Offline","cpu":"N/A","mem":"N/A","uptime":"N/A",
                "vendor":"N/A","model":"N/A","serial":"N/A"}
    d=aruba_api(ip,u,p)
    if d:
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

def poll_all(ips,u,p,comm):
    out=[]
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs={ex.submit(collect,ip,u,p,comm):ip for ip in ips}
        for fut in as_completed(futs):
            try: out.append(fut.result())
            except Exception: out.append({"ip":futs[fut],"status":"Failed","cpu":"N/A","mem":"N/A","uptime":"N/A",
                                          "vendor":"N/A","model":"N/A","serial":"N/A"})
    return out

# ---------------- Sorting & counts ----------------
def sort_devs(devs):
    for d in devs: d["status"]=norm_status(d.get("status",""))
    order={"Offline":0,"Failed":1,"Online":2}
    return sorted(devs,key=lambda d:(order.get(d["status"],3), ip_address(d["ip"])))

def counts(devs):
    t=len(devs)
    o=sum(1 for d in devs if norm_status(d["status"])=="Online")
    f=sum(1 for d in devs if norm_status(d["status"])=="Failed")
    off=sum(1 for d in devs if norm_status(d["status"])=="Offline")
    return t,o,f,off

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
        self.refresh_timer = None
        
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
        
        # Define columns
        column_ids = [col["id"] for col in COLUMNS]
        self.tree['columns'] = column_ids
        self.tree.column('#0', width=0, stretch=tk.NO)  # Hidden column
        
        # Set column headings and widths
        for col in COLUMNS:
            self.tree.column(col["id"], width=col["width"], anchor=tk.W)
            self.tree.heading(col["id"], text=col["text"], anchor=tk.W)
        
        # Status bar at the bottom
        self.status_var = tk.StringVar(value="Ready")
        self.status_bar = ttk.Label(self.main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(fill=tk.X, padx=5, pady=2)
        
        # Show login dialog at startup
        self.root.after(100, self.open_settings)

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
        
        self.status_var.set(f"Polling {len(ips)} devices...")
        self.root.update_idletasks()
        
        # Start polling in a separate thread to keep UI responsive
        self.refresh_btn.config(state=tk.DISABLED)
        
        def poll_thread():
            devices = poll_all(ips, self.api_user, self.api_pass, self.snmp_comm)
            # Update UI from the main thread
            self.root.after(0, lambda: self.update_ui(devices))
        
        import threading
        thread = threading.Thread(target=poll_thread)
        thread.daemon = True
        thread.start()

    def update_ui(self, devices):
        """Update the UI with new device data"""
        self.devices = sort_devs(devices)
        
        # Clear the treeview
        for row in self.tree.get_children():
            self.tree.delete(row)
        
        # Update summary
        t, o, f, off = counts(devices)
        self.summary_var.set(f"Summary: Total: {t} | Online: {o} | Failed: {f} | Offline: {off}")
        
        # Update last refresh time
        refresh_time = time.strftime("%Y-%m-%d %H:%M:%S")
        self.refresh_var.set(f"Last refresh: {refresh_time}")
        
        # Add device rows
        for device in self.devices:
            status = device.get("status", "")
            # Set tag for row color
            tag = status.lower() if status in ["Online", "Offline", "Failed"] else ""
            
            # Extract all values needed for the row
            values = [device.get(col["id"], "N/A") for col in COLUMNS]
            
            # Insert into tree with proper tag
            self.tree.insert('', tk.END, values=values, tags=(tag,))
        
        # Configure colors for status tags
        self.tree.tag_configure('online', background='#e0ffe0')
        self.tree.tag_configure('offline', background='#ffe0e0')
        self.tree.tag_configure('failed', background='#fff0c0')
        
        self.status_var.set(f"Ready. {t} devices loaded.")
        self.refresh_btn.config(state=tk.NORMAL)
        
        # Set timer for next refresh
        if self.refresh_timer:
            self.root.after_cancel(self.refresh_timer)
        self.refresh_timer = self.root.after(int(REFRESH_SEC * 1000), self.refresh_data)


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