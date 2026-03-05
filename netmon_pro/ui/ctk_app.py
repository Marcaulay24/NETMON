from __future__ import annotations

from datetime import datetime

try:
    import customtkinter as ctk
except Exception:  # pragma: no cover
    ctk = None


class ModernSOCApp:
    """Migration shell for CTk-based SOC interface."""

    def __init__(self):
        if ctk is None:
            raise RuntimeError("customtkinter is required for ModernSOCApp")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.root = ctk.CTk()
        self.root.title("NETMON PRO v2.1 - Modern SOC")
        self.root.geometry("1600x1000")

        self.top = ctk.CTkFrame(self.root, corner_radius=0)
        self.top.pack(fill="x")
        self.clock = ctk.CTkLabel(self.top, text="--:--:--", font=ctk.CTkFont("Segoe UI", 14, "bold"))
        self.clock.pack(side="right", padx=12, pady=8)

        self.sidebar = ctk.CTkFrame(self.root, width=240)
        self.sidebar.pack(side="left", fill="y")
        self.main = ctk.CTkFrame(self.root)
        self.main.pack(side="left", fill="both", expand=True)

        for text in ["Dashboard", "Devices", "Threat Intel", "Compliance", "Reports"]:
            ctk.CTkButton(self.sidebar, text=text, corner_radius=10).pack(fill="x", padx=10, pady=6)

        self._tick()

    def _tick(self):
        self.clock.configure(text=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        self.root.after(1000, self._tick)

    def run(self):
        self.root.mainloop()
