import threading
import datetime
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
from scapy.all import sniff, conf, get_if_list, IP, TCP, UDP, Raw

# Lista de IPs suspeitos
BLACKLISTED_IPS = {"192.168.1.100", "10.0.0.5"}

# Palavras-chave suspeitas
SUSPICIOUS_KEYWORDS = ["attack", "malware", "hacked", "exploit"]

# Portas TLS/SSL conhecidas
TLS_PORTS = {443, 465, 993, 995}

class IDSApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Sistema de Detecção de Intrusão (IDS)")
        self.root.geometry("900x650")

        # Título
        self.label = tk.Label(root, text="Sistema de Detecção de Intrusão (IDS)", font=("Arial", 16))
        self.label.pack(pady=10)

        # Seleção de interface de rede
        self.interface_label = tk.Label(root, text="Escolha a interface de rede:", font=("Arial", 12))
        self.interface_label.pack()

        self.interface_combobox = ttk.Combobox(root, values=get_if_list(), font=("Arial", 12), width=40)
        self.interface_combobox.pack(pady=5)
        self.interface_combobox.set(conf.iface)  # Define a interface padrão

        # Área de texto para logs
        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("Courier New", 10), width=100, height=25)
        self.text_area.pack(pady=10)

        # Botões de controle
        self.start_button = tk.Button(root, text="Iniciar IDS", font=("Arial", 12), command=self.start_ids)
        self.start_button.pack(pady=5)

        self.stop_button = tk.Button(root, text="Parar IDS", font=("Arial", 12), state=tk.DISABLED, command=self.stop_ids)
        self.stop_button.pack(pady=5)

        self.running = False
        self.thread = None

    def start_ids(self):
        """Inicia a captura de pacotes."""
        selected_interface = self.interface_combobox.get()
        if not selected_interface:
            messagebox.showerror("Erro", "Selecione uma interface de rede!")
            return

        self.running = True
        self.text_area.insert(tk.END, f"[+] IDS iniciado na interface {selected_interface}...\n")
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        self.thread = threading.Thread(target=self.run_ids, args=(selected_interface,), daemon=True)
        self.thread.start()

    def stop_ids(self):
        """Para a captura de pacotes."""
        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.text_area.insert(tk.END, "[+] IDS parado.\n")

    def run_ids(self, interface):
        """Captura pacotes e processa alertas."""
        def log_alert(alert):
            """Exibe e salva alertas."""
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_message = f"[{timestamp}] {alert}\n"
            self.text_area.insert(tk.END, log_message)
            self.text_area.see(tk.END)
            self.save_log(log_message)

        try:
            capture_packets(interface, log_alert)
        except Exception as e:
            if self.running:
                messagebox.showerror("Erro", f"Erro na captura de pacotes: {e}")
                self.stop_ids()

    def save_log(self, log_message):
        """Salva logs em um arquivo."""
        with open("ids_logs.txt", "a") as log_file:
            log_file.write(log_message)

# Função para analisar pacotes e gerar alertas
def detect_intrusion(packet):
    try:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            payload = str(packet[Raw].load) if Raw in packet else ""

            # Verifica IPs na lista negra
            if src_ip in BLACKLISTED_IPS or dst_ip in BLACKLISTED_IPS:
                return f"⚠️ IP suspeito detectado: {src_ip} → {dst_ip}"

            # Verifica tráfego criptografado pela porta
            if packet.haslayer(TCP) and (packet[TCP].dport in TLS_PORTS or packet[TCP].sport in TLS_PORTS):
                return f"🔒 Tráfego criptografado detectado: {src_ip} → {dst_ip} (TLS/SSL)"

            # Verifica palavras-chave suspeitas
            for keyword in SUSPICIOUS_KEYWORDS:
                if keyword.lower() in payload.lower():
                    return f"🚨 Palavra suspeita detectada: '{keyword}' em tráfego {src_ip} → {dst_ip}"

    except Exception:
        pass
    return None

# Função para capturar pacotes de rede
def capture_packets(interface, callback):
    def process_packet(packet):
        alert = detect_intrusion(packet)
        if alert:
            callback(alert)

    sniff(iface=interface, prn=process_packet, store=False)

# Inicializando a aplicação
if __name__ == "__main__":
    root = tk.Tk()
    app = IDSApp(root)
    root.mainloop()
