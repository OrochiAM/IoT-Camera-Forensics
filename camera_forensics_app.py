import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import pandas as pd
import numpy as np
from datetime import datetime
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from collections import Counter
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import seaborn as sns

class NetworkForensicApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Attack Detector & Forensic Reporter")
        self.root.geometry("1200x800")
        
        # Definicija kolona i mapiranja
        self.X_columns = [
            'flow_duration', 'Header_Length', 'Protocol Type', 'Duration',
            'Rate', 'Srate', 'Drate', 'fin_flag_number', 'syn_flag_number',
            'rst_flag_number', 'psh_flag_number', 'ack_flag_number',
            'ece_flag_number', 'cwr_flag_number', 'ack_count',
            'syn_count', 'fin_count', 'urg_count', 'rst_count', 
            'HTTP', 'HTTPS', 'DNS', 'Telnet', 'SMTP', 'SSH', 'IRC', 'TCP',
            'UDP', 'DHCP', 'ARP', 'ICMP', 'IPv', 'LLC', 'Tot sum', 'Min',
            'Max', 'AVG', 'Std', 'Tot size', 'IAT', 'Number', 'Magnitue',
            'Radius', 'Covariance', 'Variance', 'Weight'
        ]
        
        self.dict_7classes = {
            'DDoS-RSTFINFlood': 'DDoS', 'DDoS-PSHACK_Flood': 'DDoS',
            'DDoS-SYN_Flood': 'DDoS', 'DDoS-UDP_Flood': 'DDoS',
            'DDoS-TCP_Flood': 'DDoS', 'DDoS-ICMP_Flood': 'DDoS',
            'DDoS-SynonymousIP_Flood': 'DDoS', 'DDoS-ACK_Fragmentation': 'DDoS',
            'DDoS-UDP_Fragmentation': 'DDoS', 'DDoS-ICMP_Fragmentation': 'DDoS',
            'DDoS-SlowLoris': 'DDoS', 'DDoS-HTTP_Flood': 'DDoS',
            'DoS-UDP_Flood': 'DoS', 'DoS-SYN_Flood': 'DoS',
            'DoS-TCP_Flood': 'DoS', 'DoS-HTTP_Flood': 'DoS',
            'Mirai-greeth_flood': 'Mirai', 'Mirai-greip_flood': 'Mirai',
            'Mirai-udpplain': 'Mirai', 'Recon-PingSweep': 'Recon',
            'Recon-OSScan': 'Recon', 'Recon-PortScan': 'Recon',
            'VulnerabilityScan': 'Recon', 'Recon-HostDiscovery': 'Recon',
            'DNS_Spoofing': 'Spoofing', 'MITM-ArpSpoofing': 'Spoofing',
            'BenignTraffic': 'Benign', 'BrowserHijacking': 'Web',
            'Backdoor_Malware': 'Web', 'XSS': 'Web',
            'Uploading_Attack': 'Web', 'SqlInjection': 'Web',
            'CommandInjection': 'Web', 'DictionaryBruteForce': 'BruteForce'
        }
        
        self.df = None
        self.model = None
        self.scaler = StandardScaler()
        
        self.setup_ui()
        
    def setup_ui(self):
        # Stil
        style = ttk.Style()
        style.theme_use('clam')
        
        # Glavni frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Dugmad za kontrolu
        control_frame = ttk.LabelFrame(main_frame, text="Kontrole", padding="10")
        control_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Button(control_frame, text="Učitaj CSV", 
                  command=self.load_csv).grid(row=0, column=0, padx=5)
        ttk.Button(control_frame, text="Treniraj Model", 
                  command=self.train_model).grid(row=0, column=1, padx=5)
        ttk.Button(control_frame, text="Analiziraj Saobraćaj", 
                  command=self.analyze_traffic).grid(row=0, column=2, padx=5)
        ttk.Button(control_frame, text="Generiši Forenzički Izveštaj", 
                  command=self.generate_forensic_report).grid(row=0, column=3, padx=5)
        
        # Status frame
        status_frame = ttk.LabelFrame(main_frame, text="Status", padding="10")
        status_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.status_label = ttk.Label(status_frame, text="Spremno za rad")
        self.status_label.grid(row=0, column=0, sticky=tk.W)
        
        # Rezultati frame
        results_frame = ttk.LabelFrame(main_frame, text="Rezultati Analize", padding="10")
        results_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5, padx=(0, 5))
        
        self.results_text = scrolledtext.ScrolledText(results_frame, width=60, height=30)
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Vizualizacija frame
        viz_frame = ttk.LabelFrame(main_frame, text="Vizualizacija", padding="10")
        viz_frame.grid(row=2, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        self.fig, self.ax = plt.subplots(figsize=(6, 5))
        self.canvas = FigureCanvasTkAgg(self.fig, master=viz_frame)
        self.canvas.get_tk_widget().grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Konfigurisanje težina
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        viz_frame.columnconfigure(0, weight=1)
        viz_frame.rowconfigure(0, weight=1)
        
    def load_csv(self):
        file_path = filedialog.askopenfilename(
            title="Izaberite CSV fajl",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                self.df = pd.read_csv(file_path)
                self.status_label.config(text=f"Učitano {len(self.df)} redova iz {os.path.basename(file_path)}")
                self.results_text.insert(tk.END, f"✓ Učitan fajl: {os.path.basename(file_path)}\n")
                self.results_text.insert(tk.END, f"  Broj redova: {len(self.df)}\n")
                self.results_text.insert(tk.END, f"  Broj kolona: {len(self.df.columns)}\n\n")
            except Exception as e:
                messagebox.showerror("Greška", f"Greška pri učitavanju fajla:\n{str(e)}")
                
    def train_model(self):
        if self.df is None:
            messagebox.showwarning("Upozorenje", "Prvo učitajte CSV fajl!")
            return
            
        try:
            # Priprema podataka
            if 'label' in self.df.columns:
                # Mapiranje labela
                self.df['attack_category'] = self.df['label'].map(self.dict_7classes)
                
                # Filtriranje kolona koje postoje
                available_cols = [col for col in self.X_columns if col in self.df.columns]
                X = self.df[available_cols].fillna(0)
                y = self.df['attack_category']
                
                # Skaliranje
                X_scaled = self.scaler.fit_transform(X)
                
                # Treniranje modela
                self.model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
                self.model.fit(X_scaled, y)
                
                self.status_label.config(text="Model uspešno istreniran!")
                self.results_text.insert(tk.END, "✓ Model uspešno istreniran\n")
                self.results_text.insert(tk.END, f"  Korišćeno kolona: {len(available_cols)}\n")
                self.results_text.insert(tk.END, f"  Klase: {list(y.unique())}\n\n")
            else:
                messagebox.showwarning("Upozorenje", "CSV ne sadrži kolonu 'label'!")
                
        except Exception as e:
            messagebox.showerror("Greška", f"Greška pri treniranju:\n{str(e)}")
            
    def analyze_traffic(self):
        if self.df is None:
            messagebox.showwarning("Upozorenje", "Prvo učitajte CSV fajl!")
            return
            
        if self.model is None:
            messagebox.showwarning("Upozorenje", "Prvo trenirajte model!")
            return
            
        try:
            # Analiza
            available_cols = [col for col in self.X_columns if col in self.df.columns]
            X = self.df[available_cols].fillna(0)
            X_scaled = self.scaler.transform(X)
            
            predictions = self.model.predict(X_scaled)
            self.df['predicted_attack'] = predictions
            
            # Statistika
            attack_counts = Counter(predictions)
            
            self.results_text.insert(tk.END, "=" * 50 + "\n")
            self.results_text.insert(tk.END, "ANALIZA MREŽNOG SAOBRAĆAJA\n")
            self.results_text.insert(tk.END, "=" * 50 + "\n\n")
            
            for attack_type, count in attack_counts.most_common():
                percentage = (count / len(predictions)) * 100
                self.results_text.insert(tk.END, f"{attack_type:15s}: {count:6d} ({percentage:5.2f}%)\n")
            
            self.results_text.insert(tk.END, "\n")
            
            # Vizualizacija - Horizontalni bar chart
            self.ax.clear()
            attack_types = list(attack_counts.keys())
            counts = list(attack_counts.values())
            
            # Sortiranje po broju napada
            sorted_data = sorted(zip(attack_types, counts), key=lambda x: x[1], reverse=True)
            attack_types_sorted = [x[0] for x in sorted_data]
            counts_sorted = [x[1] for x in sorted_data]
            
            # Boje
            colors = sns.color_palette("husl", len(attack_types_sorted))
            
            # Horizontalni bar chart
            bars = self.ax.barh(attack_types_sorted, counts_sorted, color=colors, edgecolor='black', linewidth=1.2)
            
            # Dodavanje brojeva na kraju svakog bara
            for i, (bar, count) in enumerate(zip(bars, counts_sorted)):
                width = bar.get_width()
                percentage = (count / len(predictions)) * 100
                self.ax.text(width, bar.get_y() + bar.get_height()/2, 
                           f' {count} ({percentage:.1f}%)',
                           ha='left', va='center', fontsize=9, weight='bold')
            
            self.ax.set_xlabel('Broj Detektovanih Paketa', fontsize=10, weight='bold')
            self.ax.set_ylabel('Tip Napada', fontsize=10, weight='bold')
            self.ax.set_title('Distribucija Detektovanih Napada', fontsize=11, weight='bold', pad=15)
            self.ax.grid(axis='x', alpha=0.3, linestyle='--')
            
            self.fig.tight_layout()
            self.canvas.draw()
            
            self.status_label.config(text=f"Analizirano {len(predictions)} tokova")
            
        except Exception as e:
            messagebox.showerror("Greška", f"Greška pri analizi:\n{str(e)}")
            
    def generate_forensic_report(self):
        if self.df is None or 'predicted_attack' not in self.df.columns:
            messagebox.showwarning("Upozorenje", "Prvo analizirajte saobraćaj!")
            return
            
        try:
            report_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                initialfile=f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            )
            
            if not report_path:
                return
                
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("FORENZIČKI IZVEŠTAJ - ANALIZA MREŽNOG SAOBRAĆAJA\n")
                f.write("=" * 80 + "\n\n")
                
                f.write(f"Datum i vreme izveštaja: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Analizirano paketa: {len(self.df)}\n\n")
                
                # Statistika napada
                f.write("-" * 80 + "\n")
                f.write("STATISTIKA DETEKTOVANIH NAPADA\n")
                f.write("-" * 80 + "\n\n")
                
                attack_counts = Counter(self.df['predicted_attack'])
                for attack_type, count in attack_counts.most_common():
                    percentage = (count / len(self.df)) * 100
                    f.write(f"{attack_type:20s}: {count:8d} paketa ({percentage:6.2f}%)\n")
                
                # Detalji po tipu napada
                f.write("\n" + "-" * 80 + "\n")
                f.write("DETALJNI PODACI PO TIPU NAPADA\n")
                f.write("-" * 80 + "\n\n")
                
                for attack_type in attack_counts.keys():
                    if attack_type == 'Benign':
                        continue
                        
                    f.write(f"\n### {attack_type} ###\n")
                    attack_df = self.df[self.df['predicted_attack'] == attack_type]
                    
                    if 'Protocol Type' in attack_df.columns:
                        protocols = attack_df['Protocol Type'].value_counts()
                        f.write(f"  Protokoli: {dict(protocols)}\n")
                    
                    if 'Rate' in attack_df.columns:
                        f.write(f"  Prosečna brzina: {attack_df['Rate'].mean():.2f}\n")
                    
                    if 'Duration' in attack_df.columns:
                        f.write(f"  Prosečno trajanje: {attack_df['Duration'].mean():.2f}\n")
                    
                # Preporuke
                f.write("\n" + "-" * 80 + "\n")
                f.write("PREPORUKE ZA ZAŠTITU\n")
                f.write("-" * 80 + "\n\n")
                
                if attack_counts.get('DDoS', 0) > 0:
                    f.write("• DDoS NAPAD DETEKTOVAN\n")
                    f.write("  - Implementirajte rate limiting\n")
                    f.write("  - Koristite DDoS zaštitne servise\n")
                    f.write("  - Povećajte kapacitet bandwidth-a\n\n")
                
                if attack_counts.get('Recon', 0) > 0:
                    f.write("• RECONNAISSANCE AKTIVNOSTI DETEKTOVANE\n")
                    f.write("  - Pojačajte monitoring mrežne aktivnosti\n")
                    f.write("  - Blokirajte port scanning\n")
                    f.write("  - Implementirajte IDS/IPS sisteme\n\n")
                
                if attack_counts.get('Web', 0) > 0:
                    f.write("• WEB NAPADI DETEKTOVANI\n")
                    f.write("  - Ažurirajte web aplikacione firewall-ove\n")
                    f.write("  - Koristite input validaciju\n")
                    f.write("  - Implementirajte WAF (Web Application Firewall)\n\n")
                
                f.write("\n" + "=" * 80 + "\n")
                f.write("KRAJ IZVEŠTAJA\n")
                f.write("=" * 80 + "\n")
            
            self.results_text.insert(tk.END, f"✓ Forenzički izveštaj sačuvan: {os.path.basename(report_path)}\n\n")
            messagebox.showinfo("Uspeh", f"Izveštaj sačuvan u:\n{report_path}")
            
        except Exception as e:
            messagebox.showerror("Greška", f"Greška pri generisanju izveštaja:\n{str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkForensicApp(root)
    root.mainloop()