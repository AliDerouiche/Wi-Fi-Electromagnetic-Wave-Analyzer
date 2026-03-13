import math
import tkinter as tk
from tkinter import ttk, scrolledtext
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
import threading
import time
from datetime import datetime
import subprocess

# Log file
LOG_FILE = "wifi_log.txt"

# Write log messages
def write_log(message):
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    full_message = f"{timestamp} {message}\n"

    log_text.insert(tk.END, full_message)
    log_text.yview(tk.END)

    with open(LOG_FILE, "a") as f:
        f.write(full_message)


# Get Wi-Fi information (Windows)
def get_wifi_info():
    try:
        result = subprocess.check_output(
            "netsh wlan show interfaces", shell=True, text=True
        )

        lines = result.split("\n")
        info = {}

        for line in lines:
            if "SSID" in line and "BSSID" not in line:
                info["SSID"] = line.split(":")[1].strip()

            elif "Signal" in line:
                info["Signal"] = int(line.split(":")[1].strip().replace("%", ""))

            elif "Radio type" in line:
                info["Band"] = line.split(":")[1].strip()

            elif "Channel" in line:
                info["Channel"] = line.split(":")[1].strip()

            elif "BSSID" in line:
                info["BSSID"] = line.split(":")[1].strip()

        return info

    except Exception as e:
        return {"error": str(e)}


# Get security information
def get_security_info():
    try:
        result = subprocess.check_output(
            "netsh wlan show profile name=* key=clear",
            shell=True,
            text=True
        )

        lines = result.splitlines()

        auth = "Unknown"
        cipher = "Unknown"

        for line in lines:

            if "Authentication" in line:
                auth = line.split(":")[1].strip()

            if "Encryption" in line:
                cipher = line.split(":")[1].strip()

        return auth, cipher

    except Exception:
        return "Unknown", "Unknown"


# Electromagnetic wave equation
def electromagnetic_wave(freq_ghz):

    c = 3e8
    f = freq_ghz * 1e9

    omega = 2 * math.pi * f
    wavelength = c / f
    k = 2 * math.pi / wavelength

    expression = f"E(z,t) = E0 cos({k:.2e} z - {omega:.2e} t)"

    return expression, wavelength, k, omega


# Update GUI information
def update_info():

    wifi = get_wifi_info()

    if "error" not in wifi:

        ssid = wifi.get("SSID", "Unknown")
        signal = wifi.get("Signal", 0)
        band_type = wifi.get("Band", "").lower()

        freq = 2.4 if "a" not in band_type else 5.0

        channel = wifi.get("Channel", "N/A")

        expression, wavelength, k, omega = electromagnetic_wave(freq)

        auth, cipher = get_security_info()

        ssid_var.set(f"Network: {ssid}")
        signal_var.set(f"Signal: {signal}%")
        freq_var.set(f"Frequency: {freq} GHz (Channel {channel})")
        expr_var.set(f"Wave equation: {expression}")
        lambda_var.set(f"Wavelength: {wavelength:.3f} m")
        sec_var.set(f"Security: {auth} / {cipher}")

        plot_wave(k, omega)
        update_security_indicator(signal, auth, cipher)

    else:

        ssid_var.set("Error: Wi-Fi adapter not detected")


# Plot electromagnetic wave
def plot_wave(k, omega):

    z = np.linspace(0, 0.5, 500)
    t = 0

    E = np.cos(k * z - omega * t)

    ax.clear()
    ax.plot(z, E, label="Electric field E(z,t=0)")

    ax.set_xlabel("z (m)")
    ax.set_ylabel("E")
    ax.set_title("Electromagnetic Wave")

    ax.grid(True)
    ax.legend()

    canvas.draw()


# Security indicator
def update_security_indicator(signal, auth, cipher):

    if signal < 20 or cipher.lower() in ("open", "tkip"):

        color = "red"
        label = "Low"

    elif "wpa3" in auth.lower() or cipher.lower() == "aes":

        color = "green"
        label = "High"

    else:

        color = "orange"
        label = "Medium"

    security_label.config(
        text=f"Security level: {label}",
        foreground=color
    )


# Monitoring thread
def monitor_thread():

    global last_info

    while True:

        try:

            info = get_wifi_info()

            if not info or "error" in info:

                alert_var.set("Wi-Fi error")
                time.sleep(5)
                continue

            signal = info.get("Signal", 0)
            bssid = info.get("BSSID", "")
            channel = info.get("Channel", "")

            if last_info:

                if signal < 15:

                    msg = "[ALERT] Very weak signal (possible jamming)"
                    alert_var.set(msg)
                    write_log(msg)

                elif bssid != last_info["BSSID"]:

                    msg = "[ALERT] BSSID change detected (possible Evil Twin)"
                    alert_var.set(msg)
                    write_log(msg)

                elif channel != last_info["Channel"]:

                    msg = "[ALERT] Wi-Fi channel changed (interference or attack)"
                    alert_var.set(msg)
                    write_log(msg)

                else:

                    alert_var.set("Network stable")

            last_info = info

            time.sleep(5)

        except Exception as e:

            alert_var.set(f"Error: {e}")
            time.sleep(5)


# GUI
root = tk.Tk()
root.title("Wi-Fi Analyzer + Electromagnetic Wave")
root.geometry("700x720")
root.resizable(False, False)

ssid_var = tk.StringVar()
signal_var = tk.StringVar()
freq_var = tk.StringVar()
expr_var = tk.StringVar()
lambda_var = tk.StringVar()
alert_var = tk.StringVar()
sec_var = tk.StringVar()

ttk.Label(root, textvariable=ssid_var).pack(pady=3)
ttk.Label(root, textvariable=signal_var).pack(pady=3)
ttk.Label(root, textvariable=freq_var).pack(pady=3)
ttk.Label(root, textvariable=lambda_var).pack(pady=3)
ttk.Label(root, textvariable=expr_var, wraplength=650).pack(pady=5)
ttk.Label(root, textvariable=sec_var).pack(pady=3)

security_label = ttk.Label(root, text="", font=("Arial", 12, "bold"))
security_label.pack(pady=5)

ttk.Label(root, text="Network status").pack()
ttk.Label(root, textvariable=alert_var, foreground="red").pack(pady=3)

fig = Figure(figsize=(6.5, 2.5), dpi=100)
ax = fig.add_subplot(111)

canvas = FigureCanvasTkAgg(fig, master=root)
canvas.get_tk_widget().pack(pady=5)

ttk.Label(root, text="Event log").pack(pady=(10, 0))

log_text = scrolledtext.ScrolledText(root, height=10, width=80)
log_text.pack(pady=5)

ttk.Button(root, text="Refresh", command=update_info).pack(pady=10)

last_info = None

update_info()

threading.Thread(target=monitor_thread, daemon=True).start()

root.mainloop()
