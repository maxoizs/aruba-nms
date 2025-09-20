#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nms_live_ascii_streaming_sorted.py
- Pure ASCII/ANSI (no Rich)
- First pass: growing table with NO full-screen clears (no flicker)
  * After each device finishes -> re-sort partial list (Offline, Failed, Online) and repaint only rows
- After first pass: one clean redraw, then refresh every 60s (summary + Last refresh)
- Blinking red 🔴 for Offline between refreshes (only icon cell updates)
- REST first, SNMP fallback, ping pre-check
"""

import os, sys, re, time
from ipaddress import ip_address
from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor, as_completed
import curses
import requests, urllib3
from ping3 import ping
from pysnmp.hlapi import *

urllib3.disable_warnings()

# ---------------- Configuration ----------------
REFRESH_SEC       = 60.0
BLINK_PERIOD_SEC  = 0.7
MAX_WORKERS       = 20
IP_FILE           = "ip.txt"

# Column widths
W_IP=16; W_STATUS=8; W_VENDOR=12; W_MODEL=18; W_SERIAL=16; W_CPU=6; W_MEM=6; W_UPTIME=12

# ---------------- ANSI helpers ----------------
ESC="\033["
RESET="\033[0m"; BOLD="\033[1m"; DIM="\033[2m"
RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; CYAN="\033[36m"

def enable_ansi_on_windows():
    if os.name=="nt":
        try:
            import ctypes
            k=ctypes.windll.kernel32; h=k.GetStdHandle(-11)
            mode=ctypes.c_ulong(); k.GetConsoleMode(h, ctypes.byref(mode))
            mode.value |= 0x0004; k.SetConsoleMode(h, mode)
        except Exception: pass

def clear_screen():
    try:
        if os.name=="nt":
            try:
                import ctypes
                k=ctypes.windll.kernel32; h=k.GetStdHandle(-11)
                mode=ctypes.c_ulong(); k.GetConsoleMode(h, ctypes.byref(mode))
                mode.value |= 0x0004; k.SetConsoleMode(h, mode)
            except Exception: pass
            os.system("cls"); sys.stdout.write("\033[H")
        else:
            sys.stdout.write("\033[3J\033[2J\033[H")
        sys.stdout.flush()
    except Exception:
        sys.stdout.write("\n"*200+"\r"); sys.stdout.flush()

def mv(row:int,col:int=1): sys.stdout.write(f"{ESC}{row};{col}H")
def hide(): sys.stdout.write("\033[?25l")
def show(): sys.stdout.write("\033[?25h")
def flush(): sys.stdout.flush()

def pad(s,w,left=True):
    s="" if s is None else str(s)
    return s[:w] if len(s)>w else (s+" "*(w-len(s)) if left else " "*(w-len(s))+s)



# ----- Single-cell icons (reliable in Windows consoles) -----
#ICON_ON       = GREEN + "●" + RESET       # Online
#ICON_FAIL     = YELLOW + "▲" + RESET      # Failed
#ICON_OFF_ON   = RED + "●" + RESET         # Offline (blink ON)
#ICON_OFF_OFF  = " "                        # Offline (blink OFF) - single space



# Icons
ICON_ON  = GREEN + "✅" + RESET
ICON_FAIL= YELLOW + "⚠️" + RESET
ICON_OFF_ON = RED + "🔴" + RESET
ICON_OFF_OFF = " "  # blink off

# ---------------- SNMP helpers ----------------
def snmp_get(ip, comm, oid, timeout=1, retries=1):
    try:
        it=nextCmd(SnmpEngine(), CommunityData(comm, mpModel=1),
                  UdpTransportTarget((ip,161),timeout=timeout,retries=retries),
                  ContextData(), ObjectType(ObjectIdentity(oid)),
                  lexicographicMode=False)
        for eI,eS,eX,vb in it:
            if eI or eS: return None
            for v in vb:
                val=v[1].prettyPrint()
                if "No Such" in val: return None
                return val
    except Exception: return None

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

# ---------------- Status & icons ----------------
def norm_status(s):
    if not s: return "Failed"
    s=s.strip().lower()
    if s.startswith("on"): return "Online"
    if s.startswith("off"): return "Offline"
    if s.startswith("fail"): return "Failed"
    return "Failed"



def icon_for(status, blink_on):
    st = norm_status(status)
    if st == "Online":
        return ICON_ON
    if st == "Failed":
        return ICON_FAIL
    if st == "Offline":
        return ICON_OFF_ON if blink_on else ICON_OFF_OFF
    return ICON_FAIL


#def icon_for(status, blink_on):
 #   st=norm_status(status)
  #  if st=="Online":  return ICON_ON
   # if st=="Failed":  return ICON_FAIL
    #if st=="Offline": return ICON_OFF if blink_on else ICON_OFF_BLANK
    #return ICON_FAIL

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

def poll_streaming(ips,u,p,comm):
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs={ex.submit(collect,ip,u,p,comm):ip for ip in ips}
        for fut in as_completed(futs):
            try: yield fut.result()
            except Exception: yield {"ip":futs[fut],"status":"Failed","cpu":"N/A","mem":"N/A","uptime":"N/A",
                                     "vendor":"N/A","model":"N/A","serial":"N/A"}

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

# ---------------- Rendering ----------------
_row_pos: Dict[str,int]={}
TABLE_TOP=0
LINE_WIDTH=0
LAST_PAINTED_ROW=0

def header_text():
    return (" "+BOLD+pad("IP",W_IP)+RESET+" | "+BOLD+pad("Status",W_STATUS)+RESET+" | "+
            BOLD+pad("Vendor",W_VENDOR)+RESET+" | "+BOLD+pad("Model",W_MODEL)+RESET+" | "+
            BOLD+pad("Serial",W_SERIAL)+RESET+" | "+BOLD+pad("CPU",W_CPU,left=False)+RESET+" | "+
            BOLD+pad("Mem",W_MEM,left=False)+RESET+" | "+BOLD+pad("Uptime",W_UPTIME)+RESET)

def row_text(d, blink):
    return (f"{icon_for(d['status'], blink)} "+
            pad(d["ip"],W_IP)+" | "+
            pad(d["status"],W_STATUS)+" | "+
            pad(d.get("vendor","N/A"),W_VENDOR)+" | "+
            pad(d.get("model","N/A"),W_MODEL)+" | "+
            pad(d.get("serial","N/A"),W_SERIAL)+" | "+
            pad(d.get("cpu","N/A"),W_CPU,left=False)+" | "+
            pad(d.get("mem","N/A"),W_MEM,left=False)+" | "+
            pad(d.get("uptime","N/A"),W_UPTIME))

def print_summary(devs, last_refresh_text):
    t,o,f,off=counts(devs)
    line1=(BOLD+"Summary:"+RESET+
       f"  Total: {BOLD}{t}{RESET}  |  {ICON_ON} Online: {GREEN}{o}{RESET}  |  {ICON_FAIL} Failed: {YELLOW}{f}{RESET}  |  {ICON_OFF_ON} Offline: {RED}{off}{RESET}")

#    line1=(BOLD+"Summary:"+RESET+
 #          f"  Total: {BOLD}{t}{RESET}  |  {ICON_ON} Online: {GREEN}{o}{RESET}  |  {ICON_FAIL} Failed: {YELLOW}{f}{RESET}  |  {ICON_OFF} Offline: {RED}{off}{RESET}")
    line2=f"⏱ Last refresh: {CYAN}{last_refresh_text}{RESET}"
    sys.stdout.write(line1+"\n"+line2+"\n")

def render_header(devs, last_refresh_text):
    global TABLE_TOP, LINE_WIDTH
    clear_screen(); hide()
    print_summary(devs,last_refresh_text)
    sys.stdout.write("\n")
    hdr=header_text()
    LINE_WIDTH=len(hdr)
    sys.stdout.write(hdr+"\n")
    sys.stdout.write("-"*LINE_WIDTH+"\n")
    sys.stdout.flush()
    TABLE_TOP=6  # 2 summary + blank + header + rule

def repaint_table_in_place(devs: List[Dict[str, Any]], blink_on: bool):
    """Re-sort and repaint only the table rows area, without clearing screen."""
    global _row_pos, LAST_PAINTED_ROW
    devs_sorted = sort_devs(list(devs))

    _row_pos.clear()
    row = TABLE_TOP
    for d in devs_sorted:
        _row_pos[d["ip"]] = row
        mv(row, 1)
        sys.stdout.write(row_text(d, blink_on)+"\n")
        row += 1

    # Clear leftover old lines (if fewer rows than before)
    if LAST_PAINTED_ROW and row <= LAST_PAINTED_ROW:
        for r in range(row, LAST_PAINTED_ROW + 1):
            mv(r, 1)
            sys.stdout.write(" " * LINE_WIDTH + "\n")

    LAST_PAINTED_ROW = row - 1
    flush()
    return devs_sorted

def redraw_table(devs: List[Dict[str, Any]], blink_on: bool, last_refresh_text: str):
    """Full redraw with header (used after first pass and on timed refresh)."""
    devs_sorted = sort_devs(list(devs))
    render_header(devs_sorted, last_refresh_text)
    _row_pos.clear()
    row = TABLE_TOP
    for d in devs_sorted:
        _row_pos[d["ip"]] = row
        mv(row,1); sys.stdout.write(row_text(d, blink_on)+"\n")
        row += 1
    # update LAST_PAINTED_ROW so next streaming (if any) has correct baseline
    global LAST_PAINTED_ROW
    LAST_PAINTED_ROW = row - 1
    flush()
    return devs_sorted

def blink_icons(devs: List[Dict[str, Any]], blink_on: bool):
    for d in devs:
        row = _row_pos.get(d["ip"])
        if not row: 
            continue
        mv(row, 1)
        ico = icon_for(d["status"], blink_on)
        # ensure any leftover is cleared: icon + a trailing space
        sys.stdout.write(ico + " ")
    flush()


# ---------------- Input (non-blocking) ----------------
def read_key_nonblocking(timeout: float):
    # POSIX
    try:
        import select, termios, tty
        dr, _, _ = select.select([sys.stdin], [], [], timeout)
        if not dr: return None
        old = termios.tcgetattr(sys.stdin)
        try:
            tty.setcbreak(sys.stdin.fileno())
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old)
        return ch
    except Exception:
        # Windows
        try:
            import msvcrt
            end = time.time() + timeout
            while time.time() < end:
                if msvcrt.kbhit():
                    return msvcrt.getch().decode(errors="ignore")
                time.sleep(0.05)
            return None
        except Exception:
            time.sleep(timeout); return None

# ---------------- Main ----------------

def curses_main(stdscr):
    curses.curs_set(0)
    stdscr.clear()
    stdscr.refresh()

    stdscr.addstr(0, 0, "Aruba NMS Live Monitor (curses)", curses.A_BOLD)
    stdscr.addstr(1, 0, "API Username: ")
    stdscr.refresh()
    curses.echo()
    api_user = stdscr.getstr(1, 14, 32).decode().strip()
    stdscr.addstr(2, 0, "API Password: ")
    stdscr.refresh()
    api_pass = stdscr.getstr(2, 14, 32).decode().strip()
    stdscr.addstr(3, 0, "SNMP community (default: public): ")
    stdscr.refresh()
    snmp_comm = stdscr.getstr(3, 32, 32).decode().strip() or "public"
    curses.noecho()

    try:
        ips = read_ips()
    except Exception as e:
        stdscr.addstr(5, 0, f"Failed to read {IP_FILE}: {e}", curses.color_pair(1))
        stdscr.refresh()
        stdscr.getch()
        return

    devices: List[Dict[str,Any]] = poll_all(ips, api_user, api_pass, snmp_comm)
    last_refresh_text = time.strftime("%Y-%m-%d %H:%M:%S")

    # Print summary
    t,o,f,off = counts(devices)
    summary = f"Total: {t} | Online: {o} | Failed: {f} | Offline: {off}"
    stdscr.addstr(5, 0, summary, curses.A_BOLD)
    stdscr.addstr(6, 0, f"Last refresh: {last_refresh_text}", curses.A_DIM)

    # Print table header
    header = "IP".ljust(W_IP) + "Status".ljust(W_STATUS) + "Vendor".ljust(W_VENDOR) + "Model".ljust(W_MODEL) + "Serial".ljust(W_SERIAL) + "CPU".rjust(W_CPU) + "Mem".rjust(W_MEM) + "Uptime".ljust(W_UPTIME)
    stdscr.addstr(8, 0, header, curses.A_UNDERLINE)

    # Print device rows safely
    max_rows = curses.LINES - 3  # leave space for summary and exit prompt
    max_cols = curses.COLS - 1
    for idx, d in enumerate(devices):
        row = 9 + idx
        if row >= max_rows:
            break
        status = d.get("status", "N/A")
        color = curses.color_pair(2) if status == "Online" else curses.color_pair(3) if status == "Failed" else curses.color_pair(4)
        line = d["ip"].ljust(W_IP) + status.ljust(W_STATUS) + d.get("vendor", "N/A").ljust(W_VENDOR) + d.get("model", "N/A").ljust(W_MODEL) + d.get("serial", "N/A").ljust(W_SERIAL) + d.get("cpu", "N/A").rjust(W_CPU) + d.get("mem", "N/A").rjust(W_MEM) + d.get("uptime", "N/A").ljust(W_UPTIME)
        stdscr.addstr(row, 0, line[:max_cols], color)

    stdscr.addstr(min(row+2, curses.LINES-1), 0, "Press any key to exit.")
    stdscr.refresh()
    stdscr.getch()


def setup_curses():
    curses.initscr()
    curses.start_color()
    curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK)    # Error
    curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)  # Online
    curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK) # Failed
    curses.init_pair(4, curses.COLOR_RED, curses.COLOR_BLACK)    # Offline


if __name__ == "__main__":
    setup_curses()
    curses.wrapper(curses_main)
