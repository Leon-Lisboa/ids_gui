# ids_gui
Sistema de Detecção de Intrusão (IDS) Simples
# 📌 Sistema de Detecção de Intrusão (IDS) Simples

## 🌍 Sobre o Projeto

Este projeto é um **Sistema de Detecção de Intrusão (IDS) Simples**, desenvolvido em **Python 3.10** com interface gráfica (GUI) baseada em **Tkinter** e captura de pacotes via **Scapy**.

📡 **O IDS monitora a rede em tempo real**, analisando pacotes e detectando possíveis ameaças, incluindo:
- **IPs suspeitos**
- **Palavras-chave maliciosas** em pacotes de dados
- **Tráfego criptografado (TLS/SSL)**
- **Atividades anômalas** baseadas em padrões de comportamento

## 🚀 Funcionalidades
✅ **Captura de pacotes** em diferentes interfaces de rede (Wi-Fi, Ethernet, VPNs)  
✅ **Interface gráfica intuitiva** para iniciar e parar o IDS  
✅ **Registro de logs** com alertas de intrusão  
✅ **Detecção de tráfego criptografado (TLS/SSL)**  
✅ **Análise de pacotes suspeitos com palavras-chave maliciosas**  
✅ **Lista negra de IPs conhecidos por atividades maliciosas**  

## 🛠️ Instalação

### 🔹 1. Clone o repositório
```bash
git clone https://github.com/seuusuario/ids-python.git
cd ids-python
```

### 🔹 2. Instale as dependências
```bash
pip install scapy
sudo apt install python3-tk  # Apenas para Linux
```

### 🔹 3. Execute o programa (como administrador)
```bash
sudo python ids_gui.py
```

## 🎯 Exemplo de Saída
```
[2025-01-29 12:34:56] 🔒 Tráfego criptografado detectado: 192.168.1.2 → 142.250.190.142 (TLS/SSL)
[2025-01-29 12:35:12] ⚠️ IP suspeito detectado: 192.168.1.100 → 10.0.0.5
[2025-01-29 12:36:00] 🚨 Palavra suspeita detectada: 'hacked' em tráfego 192.168.1.5 → 172.217.29.110
```

## 📜 Licença
Este projeto está sob a licença MIT.

---

# 📌 Simple Intrusion Detection System (IDS)

## 🌍 About the Project

This project is a **Simple Intrusion Detection System (IDS)**, developed in **Python 3.10** with a **Tkinter GUI** and **packet capture using Scapy**.

📡 **The IDS monitors network traffic in real-time**, detecting potential threats such as:
- **Blacklisted IPs**
- **Malicious keywords** in data packets
- **Encrypted traffic detection (TLS/SSL)**
- **Suspicious activity patterns**

## 🚀 Features
✅ **Real-time packet capture** for Wi-Fi, Ethernet, and VPNs  
✅ **Intuitive GUI** to start and stop IDS  
✅ **Intrusion alerts and logging system**  
✅ **Encrypted traffic detection (TLS/SSL)**  
✅ **Malicious keyword analysis in network packets**  
✅ **Blacklist of known malicious IPs**  

## 🛠️ Installation

### 🔹 1. Clone the repository
```bash
git clone https://github.com/youruser/ids-python.git
cd ids-python
```

### 🔹 2. Install dependencies
```bash
pip install scapy
sudo apt install python3-tk  # Linux only
```

### 🔹 3. Run the program (as administrator)
```bash
sudo python ids_gui.py
```

## 🎯 Example Output
```
[2025-01-29 12:34:56] 🔒 Encrypted traffic detected: 192.168.1.2 → 142.250.190.142 (TLS/SSL)
[2025-01-29 12:35:12] ⚠️ Suspicious IP detected: 192.168.1.100 → 10.0.0.5
[2025-01-29 12:36:00] 🚨 Malicious keyword detected: 'hacked' in traffic 192.168.1.5 → 172.217.29.110
```

## 📜 License
This project is under the MIT license.

---

# 📌 Sistema de Detección de Intrusos (IDS) Simple

## 🌍 Sobre el Proyecto

Este proyecto es un **Sistema de Detección de Intrusos (IDS) Simple**, desarrollado en **Python 3.10** con una **interfaz gráfica Tkinter** y **captura de paquetes con Scapy**.

📡 **El IDS monitorea la red en tiempo real**, detectando amenazas como:
- **IPs sospechosas**
- **Palabras clave maliciosas** en paquetes de datos
- **Detección de tráfico encriptado (TLS/SSL)**
- **Patrones de actividad anómalos**

## 🚀 Funcionalidades
✅ **Captura de paquetes en tiempo real** para Wi-Fi, Ethernet y VPNs  
✅ **Interfaz gráfica intuitiva** para iniciar y detener el IDS  
✅ **Sistema de alertas y registro de intrusiones**  
✅ **Detección de tráfico encriptado (TLS/SSL)**  
✅ **Análisis de palabras clave maliciosas en los paquetes de red**  
✅ **Lista negra de IPs conocidas por actividades maliciosas**  

## 🛠️ Instalación

### 🔹 1. Clonar el repositorio
```bash
git clone https://github.com/tuusuario/ids-python.git
cd ids-python
```

### 🔹 2. Instalar dependencias
```bash
pip install scapy
sudo apt install python3-tk  # Solo en Linux
```

### 🔹 3. Ejecutar el programa (como administrador)
```bash
sudo python ids_gui.py
```

## 🎯 Ejemplo de Salida
```
[2025-01-29 12:34:56] 🔒 Tráfico encriptado detectado: 192.168.1.2 → 142.250.190.142 (TLS/SSL)
[2025-01-29 12:35:12] ⚠️ IP sospechosa detectada: 192.168.1.100 → 10.0.0.5
[2025-01-29 12:36:00] 🚨 Palabra clave maliciosa detectada: 'hacked' en tráfico 192.168.1.5 → 172.217.29.110
```

## 📜 Licencia
Este proyecto está bajo la licencia MIT.
