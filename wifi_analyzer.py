"""
wifi_analyzer.py
WiFi Security & EM Wave Analyzer — Windows (netsh)
Features: real-time monitoring, signal history chart, EM wave visualization,
          threat detection (Evil Twin / Jamming / Channel Change), event log export.
Run as Administrator with Location Services enabled for full functionality.
"""

# ============================================================ #
#  Imports                                                      #
# ============================================================ #

import math
import subprocess
import threading
import time
import tkinter as tk
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from tkinter import ttk, scrolledtext, messagebox, filedialog

import numpy as np
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure


# ============================================================ #
#  MODULE 1 — Network: WiFi info retrieval                      #
# ============================================================ #

def get_wifi_info() -> dict:
    """
    Returns active WiFi interface information via netsh.
    Compatible with both French and English Windows.
    Keys: SSID, Signal (int %), Band, Channel, BSSID — or {"error": ...}
    """
    try:
        result = subprocess.check_output(
            "netsh wlan show interfaces",
            shell=True, text=True, encoding="utf-8", errors="replace"
        )
        info = {}
        for line in result.split("\n"):
            stripped = line.strip()
            if not stripped or ":" not in stripped:
                continue
            key, _, value = stripped.partition(":")
            k = key.strip().lower()
            v = value.strip()

            if ("ssid" in k or k == "nom") and "bssid" not in k:
                info["SSID"] = v
            elif k == "signal":
                try:
                    info["Signal"] = int(v.replace("%", "").strip())
                except ValueError:
                    pass
            elif "radio" in k or "type de radio" in k:
                info["Band"] = v
            elif k in ("canal", "channel"):
                info["Channel"] = v
            elif "bssid" in k:
                info["BSSID"] = v
            elif "receive rate" in k or "débit" in k:
                info["RxRate"] = v
            elif "transmit rate" in k or "émission" in k:
                info["TxRate"] = v

        return info if info else {"error": "No WiFi information found"}

    except Exception as e:
        return {"error": str(e)}


def get_security_info() -> tuple[str, str]:
    """Returns (authentication, cipher) for the active WiFi profile. FR/EN."""
    try:
        result = subprocess.check_output(
            "netsh wlan show profile name=* key=clear",
            shell=True, text=True, encoding="utf-8", errors="replace"
        )
        auth, cipher = "Unknown", "Unknown"
        for line in result.splitlines():
            if ":" not in line:
                continue
            k, _, v = line.strip().partition(":")
            kl = k.strip().lower()
            val = v.strip()
            if "authentification" in kl or "authentication" in kl:
                auth = val
            elif "chiffrement" in kl or "encryption" in kl or "cipher" in kl:
                cipher = val
        return auth, cipher
    except Exception:
        return "Unknown", "Unknown"


# ============================================================ #
#  MODULE 2 — Physics: EM wave calculations                     #
# ============================================================ #

@dataclass
class WaveParameters:
    frequency_ghz:     float
    wavelength:        float   # λ in meters
    wave_number:       float   # k = 2π/λ
    angular_frequency: float   # ω = 2πf
    expression:        str


def compute_wave(freq_ghz: float) -> WaveParameters:
    """
    Computes EM wave parameters for a given frequency in GHz.
    Model: E(z, t) = E₀ cos(kz − ωt)
    """
    c     = 3e8
    f     = freq_ghz * 1e9
    omega = 2 * math.pi * f
    lam   = c / f
    k     = 2 * math.pi / lam
    expr  = (f"E(z,t) = E\u2080 cos({k:.2e}\u00b7z "
             f"\u2212 {omega:.2e}\u00b7t)")
    return WaveParameters(freq_ghz, lam, k, omega, expr)


def band_to_frequency(band_type: str) -> float:
    """Infers frequency (2.4 or 5.0 GHz) from the netsh band string."""
    b = band_type.lower()
    if any(tag in b for tag in ("802.11a", "802.11ac", "802.11ax", "5 ghz", "5ghz")):
        return 5.0
    return 2.4


def signal_to_dbm(percent: int) -> float:
    """Converts Windows signal percentage to approximate dBm."""
    return (percent / 2) - 100


# ============================================================ #
#  MODULE 3 — Security: threat assessment                       #
# ============================================================ #

class SecurityLevel(Enum):
    HIGH   = ("High",   "#27ae60")
    MEDIUM = ("Medium", "#e67e22")
    LOW    = ("Low",    "#e74c3c")

    def __init__(self, label: str, color: str):
        self.label = label
        self.color = color


@dataclass
class ThreatEvent:
    alert_type: str
    message:    str
    severity:   str = "WARNING"   # INFO | WARNING | CRITICAL


def assess_security(signal: int, auth: str, cipher: str) -> SecurityLevel:
    """Rates the security level based on signal strength and protocol."""
    if signal < 20 or cipher.lower() in ("open", "tkip", "ouvert"):
        return SecurityLevel.LOW
    if "wpa3" in auth.lower() or cipher.lower() in ("aes", "ccmp"):
        return SecurityLevel.HIGH
    return SecurityLevel.MEDIUM


def detect_threats(current: dict, previous: dict | None) -> list[ThreatEvent]:
    """
    Compares two consecutive network states.
    Returns a list of ThreatEvents (empty if network is stable).
    """
    if previous is None:
        return []

    threats = []
    signal  = current.get("Signal",  100)
    bssid   = current.get("BSSID",   "")
    channel = current.get("Channel", "")

    if signal < 15:
        threats.append(ThreatEvent(
            "JAMMING",
            "[CRITICAL] Very low signal — possible jamming attack",
            "CRITICAL"
        ))
    if bssid and bssid != previous.get("BSSID", ""):
        threats.append(ThreatEvent(
            "EVIL_TWIN",
            "[WARNING] BSSID change detected — possible Evil Twin attack",
            "WARNING"
        ))
    if channel and channel != previous.get("Channel", ""):
        threats.append(ThreatEvent(
            "CHANNEL_CHANGE",
            "[INFO] WiFi channel changed — interference or attack",
            "INFO"
        ))
    return threats


# ============================================================ #
#  MODULE 4 — Logger: file + Tkinter widget                     #
# ============================================================ #

LOG_FILE = Path("wifi_log.txt")


class EventLogger:
    """Writes events to a text file and optionally to a GUI widget."""

    def __init__(self, log_widget=None):
        self._widget = log_widget
        self._entries: list[str] = []

    def attach_widget(self, widget) -> None:
        self._widget = widget

    def log(self, message: str, level: str = "INFO") -> None:
        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        full = f"{timestamp} [{level}] {message}\n"
        self._entries.append(full)

        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(full)

        if self._widget is not None:
            tag = level.lower()
            self._widget.insert("end", full, tag)
            self._widget.yview("end")

    def export(self, path: Path) -> None:
        """Exports all log entries to a chosen file."""
        with path.open("w", encoding="utf-8") as f:
            f.writelines(self._entries)


# ============================================================ #
#  MODULE 5 — Monitor: background network surveillance thread   #
# ============================================================ #

@dataclass
class MonitorStats:
    """Tracks running statistics for the monitoring session."""
    start_time:    datetime = field(default_factory=datetime.now)
    total_checks:  int = 0
    total_threats: int = 0
    min_signal:    int = 100
    max_signal:    int = 0

    def update(self, signal: int, threats: list) -> None:
        self.total_checks  += 1
        self.total_threats += len(threats)
        self.min_signal     = min(self.min_signal, signal)
        self.max_signal     = max(self.max_signal, signal)

    @property
    def uptime(self) -> str:
        delta = datetime.now() - self.start_time
        h, rem = divmod(int(delta.total_seconds()), 3600)
        m, s   = divmod(rem, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"


class NetworkMonitor:
    """
    Background WiFi surveillance thread.
    Fires on_threats(list) / on_stable() / on_error(str) callbacks.
    """

    def __init__(self, on_threats, on_stable, on_error,
                 on_signal_update, interval: int = 5):
        self._on_threats       = on_threats
        self._on_stable        = on_stable
        self._on_error         = on_error
        self._on_signal_update = on_signal_update
        self._interval         = interval
        self._last_info: dict | None = None
        self.stats = MonitorStats()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _run(self) -> None:
        while True:
            try:
                info = get_wifi_info()
                if not info or "error" in info:
                    self._on_error("WiFi error — interface unavailable")
                    time.sleep(self._interval)
                    continue

                signal  = info.get("Signal", 0)
                threats = detect_threats(info, self._last_info)

                self._on_signal_update(signal)
                self.stats.update(signal, threats)

                if threats:
                    self._on_threats(threats)
                else:
                    self._on_stable()

                self._last_info = info

            except Exception as e:
                self._on_error(f"Monitor error: {e}")

            time.sleep(self._interval)


# ============================================================ #
#  MODULE 6 — WavePlot: Matplotlib EM wave widget               #
# ============================================================ #

class WavePlot:
    """Matplotlib canvas embedded in a Tkinter parent widget."""

    def __init__(self, parent):
        self._fig = Figure(figsize=(6.5, 2.3), dpi=100)
        self._fig.patch.set_facecolor("#1e1e2e")
        self._ax = self._fig.add_subplot(111)
        self._canvas = FigureCanvasTkAgg(self._fig, master=parent)
        self._canvas.get_tk_widget().pack(pady=4, padx=10, fill="x")

    def update(self, k: float, omega: float,
               freq_ghz: float, t: float = 0) -> None:
        """Redraws E(z, t) over [0, 0.5 m]."""
        z     = np.linspace(0, 0.5, 500)
        E     = np.cos(k * z - omega * t)
        color = "#00d4ff" if freq_ghz >= 5.0 else "#ff6b35"

        ax = self._ax
        ax.clear()
        ax.set_facecolor("#1e1e2e")
        ax.plot(z, E, color=color, linewidth=1.8,
                label=f"E(z, t=0)  —  {freq_ghz} GHz")
        ax.fill_between(z, E, alpha=0.12, color=color)
        ax.set_xlabel("z (m)", color="#aaaaaa", fontsize=8)
        ax.set_ylabel("E (normalized)", color="#aaaaaa", fontsize=8)
        ax.set_title("Electromagnetic Wave", color="#ffffff",
                     fontsize=9, fontweight="bold")
        ax.tick_params(colors="#888888", labelsize=7)
        ax.spines[:].set_color("#444444")
        ax.grid(True, alpha=0.2, color="#555555")
        legend = ax.legend(fontsize=8, facecolor="#2a2a3e",
                           edgecolor="#555555", labelcolor="#ffffff")
        self._fig.tight_layout(pad=0.8)
        self._canvas.draw()

    def draw_default(self) -> None:
        """Shows a 2.4 GHz wave as placeholder."""
        wave = compute_wave(2.4)
        self.update(wave.wave_number, wave.angular_frequency, 2.4)


# ============================================================ #
#  MODULE 7 — SignalHistoryPlot: live signal strength chart     #
# ============================================================ #

class SignalHistoryPlot:
    """
    Live rolling signal-strength chart (last 60 samples).
    Color-coded: green > 60%, orange 30–60%, red < 30%.
    """

    HISTORY_SIZE = 60

    def __init__(self, parent):
        self._history: deque[int] = deque(maxlen=self.HISTORY_SIZE)
        self._fig = Figure(figsize=(6.5, 1.8), dpi=100)
        self._fig.patch.set_facecolor("#1e1e2e")
        self._ax  = self._fig.add_subplot(111)
        self._canvas = FigureCanvasTkAgg(self._fig, master=parent)
        self._canvas.get_tk_widget().pack(pady=4, padx=10, fill="x")

    def push(self, signal: int) -> None:
        self._history.append(signal)
        self._redraw()

    def _redraw(self) -> None:
        data = list(self._history)
        xs   = list(range(len(data)))
        ax   = self._ax
        ax.clear()
        ax.set_facecolor("#1e1e2e")

        # Color segments
        for i in range(1, len(data)):
            v = data[i]
            c = "#27ae60" if v >= 60 else ("#e67e22" if v >= 30 else "#e74c3c")
            ax.fill_between([xs[i-1], xs[i]], [data[i-1], data[i]],
                            alpha=0.25, color=c)
            ax.plot([xs[i-1], xs[i]], [data[i-1], data[i]],
                    color=c, linewidth=1.6)

        ax.set_xlim(0, self.HISTORY_SIZE)
        ax.set_ylim(0, 100)
        ax.set_ylabel("Signal %", color="#aaaaaa", fontsize=8)
        ax.set_title("Signal History (last 60 samples)",
                     color="#ffffff", fontsize=9, fontweight="bold")
        ax.tick_params(colors="#888888", labelsize=7)
        ax.spines[:].set_color("#444444")
        ax.grid(True, alpha=0.2, color="#555555", axis="y")
        ax.axhline(60, color="#27ae60", linewidth=0.7,
                   linestyle="--", alpha=0.5)
        ax.axhline(30, color="#e74c3c", linewidth=0.7,
                   linestyle="--", alpha=0.5)
        self._fig.tight_layout(pad=0.6)
        self._canvas.draw()


# ============================================================ #
#  MODULE 8 — WiFiAnalyzerApp: main GUI application             #
# ============================================================ #

DARK_BG   = "#1e1e2e"
CARD_BG   = "#2a2a3e"
TEXT_FG   = "#cdd6f4"
ACCENT    = "#89b4fa"
FONT_MONO = ("Consolas", 9)
FONT_UI   = ("Segoe UI", 10)
FONT_HEAD = ("Segoe UI", 11, "bold")


class WiFiAnalyzerApp:
    """Main window — orchestrates all modules."""

    def __init__(self):
        self._root = tk.Tk()
        self._root.title("WiFi Security & EM Analyzer")
        self._root.geometry("720x900")
        self._root.resizable(False, True)
        self._root.configure(bg=DARK_BG)

        self._style_ttk()
        self._build_variables()
        self._build_ui()

        self._logger = EventLogger()
        self._logger.attach_widget(self._log_widget)

        self._monitor = NetworkMonitor(
            on_threats       = self._on_threats,
            on_stable        = self._on_stable,
            on_error         = self._on_network_error,
            on_signal_update = self._on_signal_update,
        )

    # -------------------------------------------------------- #
    #  TTK Dark Theme                                           #
    # -------------------------------------------------------- #

    def _style_ttk(self) -> None:
        s = ttk.Style(self._root)
        s.theme_use("clam")
        s.configure(".",
            background=DARK_BG, foreground=TEXT_FG,
            fieldbackground=CARD_BG, font=FONT_UI)
        s.configure("TLabel",
            background=DARK_BG, foreground=TEXT_FG)
        s.configure("Card.TFrame",
            background=CARD_BG, relief="flat")
        s.configure("Accent.TButton",
            background=ACCENT, foreground=DARK_BG,
            font=("Segoe UI", 10, "bold"), padding=6)
        s.map("Accent.TButton",
            background=[("active", "#74c7ec")])
        s.configure("TScrollbar",
            background=CARD_BG, troughcolor=DARK_BG,
            arrowcolor=TEXT_FG)

    # -------------------------------------------------------- #
    #  Tkinter Variables                                        #
    # -------------------------------------------------------- #

    def _build_variables(self) -> None:
        self._ssid_var    = tk.StringVar(value="—")
        self._signal_var  = tk.StringVar(value="—")
        self._dbm_var     = tk.StringVar(value="—")
        self._freq_var    = tk.StringVar(value="—")
        self._channel_var = tk.StringVar(value="—")
        self._band_var    = tk.StringVar(value="—")
        self._lambda_var  = tk.StringVar(value="—")
        self._expr_var    = tk.StringVar(value="—")
        self._sec_var     = tk.StringVar(value="—")
        self._alert_var   = tk.StringVar(value="Initializing…")
        self._uptime_var  = tk.StringVar(value="00:00:00")
        self._checks_var  = tk.StringVar(value="0")
        self._threats_var = tk.StringVar(value="0")

    # -------------------------------------------------------- #
    #  UI Construction                                          #
    # -------------------------------------------------------- #

    def _build_ui(self) -> None:
        # ── Title bar ──────────────────────────────────────── #
        title_frame = tk.Frame(self._root, bg=DARK_BG)
        title_frame.pack(fill="x", padx=14, pady=(12, 4))
        tk.Label(title_frame, text="📡  WiFi Security & EM Analyzer",
                 bg=DARK_BG, fg=ACCENT,
                 font=("Segoe UI", 14, "bold")).pack(side="left")
        tk.Label(title_frame,
                 text="Real-time monitoring · Threat detection · EM physics",
                 bg=DARK_BG, fg="#6c7086",
                 font=("Segoe UI", 9)).pack(side="left", padx=10)

        # ── Network info card ─────────────────────────────── #
        self._card("Network Information", self._build_network_card)

        # ── Security card ─────────────────────────────────── #
        self._card("Security", self._build_security_card)

        # ── EM Wave card ──────────────────────────────────── #
        self._card("Electromagnetic Wave", self._build_wave_card)

        # ── Signal history card ───────────────────────────── #
        self._card("Signal History", self._build_signal_history_card)

        # ── Session stats ─────────────────────────────────── #
        self._card("Session Statistics", self._build_stats_card)

        # ── Event log ─────────────────────────────────────── #
        self._card("Event Log", self._build_log_card)

        # ── Buttons ───────────────────────────────────────── #
        btn_frame = tk.Frame(self._root, bg=DARK_BG)
        btn_frame.pack(fill="x", padx=14, pady=8)
        ttk.Button(btn_frame, text="⟳  Refresh",
                   style="Accent.TButton",
                   command=self._refresh).pack(side="left", padx=(0, 8))
        ttk.Button(btn_frame, text="💾  Export Log",
                   command=self._export_log).pack(side="left")

        # Uptime ticker
        self._tick_uptime()

    def _card(self, title: str, builder) -> None:
        """Creates a titled card frame and calls builder(frame)."""
        outer = tk.Frame(self._root, bg=DARK_BG)
        outer.pack(fill="x", padx=14, pady=4)
        tk.Label(outer, text=title.upper(), bg=DARK_BG,
                 fg="#6c7086",
                 font=("Segoe UI", 8, "bold")).pack(anchor="w")
        inner = tk.Frame(outer, bg=CARD_BG,
                         highlightbackground="#313244",
                         highlightthickness=1)
        inner.pack(fill="x")
        builder(inner)

    # ── Card builders ─────────────────────────────────────── #

    def _build_network_card(self, f: tk.Frame) -> None:
        grid = tk.Frame(f, bg=CARD_BG)
        grid.pack(fill="x", padx=12, pady=8)

        def row(label, var, r, c=0):
            tk.Label(grid, text=label, bg=CARD_BG,
                     fg="#6c7086", font=FONT_UI,
                     width=14, anchor="w").grid(
                         row=r, column=c*2, sticky="w", pady=2)
            tk.Label(grid, textvariable=var, bg=CARD_BG,
                     fg=TEXT_FG, font=FONT_UI,
                     anchor="w").grid(
                         row=r, column=c*2+1, sticky="w", padx=(4, 20))

        row("SSID",      self._ssid_var,    0, 0)
        row("Signal",    self._signal_var,  1, 0)
        row("dBm (est)", self._dbm_var,     2, 0)
        row("Frequency", self._freq_var,    0, 1)
        row("Channel",   self._channel_var, 1, 1)
        row("Band",      self._band_var,    2, 1)

    def _build_security_card(self, f: tk.Frame) -> None:
        inner = tk.Frame(f, bg=CARD_BG)
        inner.pack(fill="x", padx=12, pady=8)

        tk.Label(inner, text="Protocol / Cipher:",
                 bg=CARD_BG, fg="#6c7086",
                 font=FONT_UI).pack(side="left")
        tk.Label(inner, textvariable=self._sec_var,
                 bg=CARD_BG, fg=TEXT_FG,
                 font=FONT_UI).pack(side="left", padx=8)

        self._security_label = tk.Label(
            inner, text="", bg=CARD_BG,
            font=("Segoe UI", 10, "bold"))
        self._security_label.pack(side="right", padx=8)

        # Alert line
        alert_frame = tk.Frame(f, bg=CARD_BG)
        alert_frame.pack(fill="x", padx=12, pady=(0, 8))
        tk.Label(alert_frame, text="Status:",
                 bg=CARD_BG, fg="#6c7086",
                 font=FONT_UI).pack(side="left")
        self._alert_label = tk.Label(
            alert_frame, textvariable=self._alert_var,
            bg=CARD_BG, fg="#a6e3a1",
            font=("Segoe UI", 10, "bold"))
        self._alert_label.pack(side="left", padx=8)

    def _build_wave_card(self, f: tk.Frame) -> None:
        info = tk.Frame(f, bg=CARD_BG)
        info.pack(fill="x", padx=12, pady=(8, 0))

        def lbl(text, var, side="left", padx=16):
            tk.Label(info, text=text, bg=CARD_BG,
                     fg="#6c7086", font=FONT_UI).pack(side=side)
            tk.Label(info, textvariable=var, bg=CARD_BG,
                     fg=TEXT_FG, font=FONT_UI).pack(
                         side=side, padx=(2, padx))

        lbl("λ =",      self._lambda_var)
        lbl("Expr:",    self._expr_var)

        self._wave_plot = WavePlot(f)

    def _build_signal_history_card(self, f: tk.Frame) -> None:
        self._signal_history_plot = SignalHistoryPlot(f)

    def _build_stats_card(self, f: tk.Frame) -> None:
        g = tk.Frame(f, bg=CARD_BG)
        g.pack(fill="x", padx=12, pady=8)

        def stat(label, var, col):
            tk.Label(g, text=label, bg=CARD_BG,
                     fg="#6c7086", font=FONT_UI,
                     width=16, anchor="w").grid(
                         row=0, column=col*2, sticky="w")
            tk.Label(g, textvariable=var, bg=CARD_BG,
                     fg=ACCENT, font=("Segoe UI", 10, "bold"),
                     anchor="w").grid(
                         row=0, column=col*2+1, sticky="w", padx=(4, 24))

        stat("Uptime",          self._uptime_var,  0)
        stat("Checks",          self._checks_var,  1)
        stat("Threats detected",self._threats_var, 2)

    def _build_log_card(self, f: tk.Frame) -> None:
        self._log_widget = scrolledtext.ScrolledText(
            f, height=8, width=82,
            bg="#11111b", fg=TEXT_FG,
            insertbackground=TEXT_FG,
            font=FONT_MONO, relief="flat",
            state="normal"
        )
        self._log_widget.pack(padx=8, pady=8)
        # Color tags
        self._log_widget.tag_config("critical", foreground="#f38ba8")
        self._log_widget.tag_config("warning",  foreground="#fab387")
        self._log_widget.tag_config("info",     foreground="#a6e3a1")

    # -------------------------------------------------------- #
    #  Data refresh                                             #
    # -------------------------------------------------------- #

    def _refresh(self) -> None:
        """Refreshes all displayed information."""
        wifi = get_wifi_info()

        if "error" in wifi:
            self._ssid_var.set(f"Error: {wifi['error']}")
            self._alert_var.set("WiFi card not detected or access denied")
            self._alert_label.config(fg="#f38ba8")
            self._wave_plot.draw_default()
            self._logger.log(wifi["error"], "CRITICAL")
            return

        ssid    = wifi.get("SSID",    "Unknown")
        signal  = wifi.get("Signal",  0)
        channel = wifi.get("Channel", "N/A")
        band    = wifi.get("Band",    "")
        rx      = wifi.get("RxRate",  "N/A")
        tx      = wifi.get("TxRate",  "N/A")
        freq    = band_to_frequency(band)
        dbm     = signal_to_dbm(signal)

        auth, cipher = get_security_info()
        wave  = compute_wave(freq)
        level = assess_security(signal, auth, cipher)

        # Update all vars
        self._ssid_var.set(ssid)
        self._signal_var.set(f"{signal}%")
        self._dbm_var.set(f"{dbm:.1f} dBm")
        self._freq_var.set(f"{freq} GHz")
        self._channel_var.set(channel)
        self._band_var.set(band or "N/A")
        self._lambda_var.set(f"{wave.wavelength*100:.2f} cm")
        self._expr_var.set(wave.expression)
        self._sec_var.set(f"{auth} / {cipher}")

        self._security_label.config(
            text=f"●  {level.label}",
            fg=level.color
        )

        self._wave_plot.update(
            wave.wave_number, wave.angular_frequency, freq
        )
        self._signal_history_plot.push(signal)
        self._logger.log(
            f"Refresh — SSID: {ssid} | Signal: {signal}% ({dbm:.1f} dBm) "
            f"| {freq} GHz Ch{channel} | Security: {level.label}",
            "INFO"
        )

    # -------------------------------------------------------- #
    #  Monitor callbacks                                        #
    # -------------------------------------------------------- #

    def _on_threats(self, threats: list[ThreatEvent]) -> None:
        msgs = " | ".join(t.message for t in threats)
        self._alert_var.set(msgs)
        self._alert_label.config(fg="#f38ba8")
        for t in threats:
            self._logger.log(t.message, t.severity)
        self._threats_var.set(
            str(self._monitor.stats.total_threats)
        )

    def _on_stable(self) -> None:
        self._alert_var.set("✓  Network stable")
        self._alert_label.config(fg="#a6e3a1")
        self._checks_var.set(str(self._monitor.stats.total_checks))

    def _on_network_error(self, message: str) -> None:
        self._alert_var.set(message)
        self._alert_label.config(fg="#f38ba8")

    def _on_signal_update(self, signal: int) -> None:
        """Called every monitor tick to push a new signal sample."""
        self._root.after(0, self._signal_history_plot.push, signal)
        self._checks_var.set(str(self._monitor.stats.total_checks))

    # -------------------------------------------------------- #
    #  Utilities                                                #
    # -------------------------------------------------------- #

    def _tick_uptime(self) -> None:
        """Updates the uptime counter every second."""
        if hasattr(self, "_monitor"):
            self._uptime_var.set(self._monitor.stats.uptime)
        self._root.after(1000, self._tick_uptime)

    def _export_log(self) -> None:
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Export Event Log"
        )
        if path:
            self._logger.export(Path(path))
            messagebox.showinfo("Export", f"Log exported to:\n{path}")

    # -------------------------------------------------------- #
    #  Launch                                                   #
    # -------------------------------------------------------- #

    def run(self) -> None:
        self._refresh()
        self._monitor.start()
        self._root.mainloop()


# ============================================================ #
#  Entry point                                                  #
# ============================================================ #

if __name__ == "__main__":
    WiFiAnalyzerApp().run()
