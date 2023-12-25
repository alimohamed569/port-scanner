import tkinter as tk
from tkinter import ttk
import threading  # Add this line to import threading module
from concurrent.futures import ThreadPoolExecutor
import queue
import socket
import scapy.all as scapy


class NetworkScannerGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Network Scanner")

        self.ip_label = ttk.Label(master, text="Enter IP address or network range:")
        self.ip_label.grid(row=0, column=0, padx=10, pady=10)

        self.ip_entry = ttk.Entry(master)
        self.ip_entry.grid(row=0, column=1, padx=10, pady=10)

        self.scan_button = ttk.Button(master, text="Scan", command=self.start_scan)
        self.scan_button.grid(row=0, column=2, padx=10, pady=10)

        self.result_text = tk.Text(master, height=10, width=50)
        self.result_text.grid(row=1, column=0, columnspan=3, padx=10, pady=10)

        self.queue = queue.Queue()

        self.scan_thread = None

    def start_scan(self):
        ip_to_scan = self.ip_entry.get()
        self.result_text.delete(1.0, tk.END)  # Clear previous results

        self.scan_thread = threading.Thread(target=self.scan_network, args=(ip_to_scan,))
        self.scan_thread.start()
        self.master.after(100, self.check_queue)

    def scan_network(self, ip):
        try:
            connected_devices = self.scan(ip)
            self.display_result(connected_devices)
            self.scan_ports(connected_devices)
        except Exception as e:
            self.queue.put(f"An error occurred: {e}")

    def scan(self, ip):
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        clients_list = [{"ip": element[1].psrc, "mac": element[1].hwsrc} for element in answered_list]
        return clients_list

    def display_result(self, results):
        self.queue.put("Connected Devices:")
        self.queue.put("IP Address\t\tMAC Address")
        self.queue.put("----------------------------------------------------")
        for client in results:
            self.queue.put(f"{client['ip']}\t\t{client['mac']}")

    def scan_ports(self, target_ip_list):
        for client in target_ip_list:
            ip_to_scan = client["ip"]
            self.queue.put(f"\nScanning ports for {ip_to_scan} ({client['mac']})")
            open_ports = []

            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = [executor.submit(self.scan_port, ip_to_scan, port) for port in range(1, 1024)]

                for future in futures:
                    port, is_open, service_name = future.result()
                    if is_open:
                        open_ports.append(port)
                        self.queue.put(f"Port {port} ({service_name}) is open")

            if not open_ports:
                self.queue.put("No open ports found.")

    def scan_port(self, ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        service_name = socket.getservbyport(port, 'tcp') if result == 0 else "unknown"
        sock.close()
        return port, result == 0, service_name

    def check_queue(self):
        try:
            message = self.queue.get(0)
            self.result_text.insert(tk.END, message + "\n")
            self.master.after(100, self.check_queue)
        except queue.Empty:
            self.master.after(100, self.check_queue)


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerGUI(root)
    root.mainloop()
