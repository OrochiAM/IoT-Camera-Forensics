import matplotlib
matplotlib.use("TkAgg")
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import pandas as pd
import numpy as np
from datetime import datetime
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class NetworkForensicApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Detektor Mrežnih Napada i Forenzički Izveštaj")
        self.root.geometry("1400x900")
        
        # Modern color scheme
        self.colors = {
            'bg': '#1e1e2e',
            'fg': '#cdd6f4',
            'accent': '#89b4fa',
            'success': '#a6e3a1',
            'warning': '#f9e2af',
            'danger': '#f38ba8',
            'camera': '#ff6b9d',
            'card': '#313244',
            'hover': '#45475a'
        }
        
        self.root.configure(bg=self.colors['bg'])
        
        # Definicija kolona i mapiranja
        self.X_columns = [
            'flow_duration', 'Header_Length', 'Protocol Type', 'Duration',
            'Rate', 'Srate', 'Drate', 'fin_flag_number', 'syn_flag_number',
            'rst_flag_number', 'psh_flag_number', 'ack_flag_number',
            'ece_flag_number', 'cwr_flag_number', 'ack_count', 'syn_count',
            'fin_count', 'urg_count', 'rst_count', 'HTTP', 'HTTPS', 'DNS',
            'Telnet', 'SMTP', 'SSH', 'IRC', 'TCP', 'UDP', 'DHCP', 'ARP',
            'ICMP', 'IPv', 'LLC', 'Tot sum', 'Min', 'Max', 'AVG', 'Std',
            'Tot size', 'IAT', 'Number', 'Magnitue', 'Radius', 'Covariance',
            'Variance', 'Weight'
        ]
        
        self.dict_7classes = {
            'DDoS-RSTFINFlood': 'DDoS',
            'DDoS-PSHACK_Flood': 'DDoS',
            'DDoS-SYN_Flood': 'DDoS',
            'DDoS-UDP_Flood': 'DDoS',
            'DDoS-TCP_Flood': 'DDoS',
            'DDoS-ICMP_Flood': 'DDoS',
            'DDoS-SynonymousIP_Flood': 'DDoS',
            'DDoS-ACK_Fragmentation': 'DDoS',
            'DDoS-UDP_Fragmentation': 'DDoS',
            'DDoS-ICMP_Fragmentation': 'DDoS',
            'DDoS-SlowLoris': 'DDoS',
            'DDoS-HTTP_Flood': 'DDoS',
            'DoS-UDP_Flood': 'DoS',
            'DoS-SYN_Flood': 'DoS',
            'DoS-TCP_Flood': 'DoS',
            'DoS-HTTP_Flood': 'DoS',
            'Mirai-greeth_flood': 'Mirai',
            'Mirai-greip_flood': 'Mirai',
            'Mirai-udpplain': 'Mirai',
            'Recon-PingSweep': 'Recon',
            'Recon-OSScan': 'Recon',
            'Recon-PortScan': 'Recon',
            'VulnerabilityScan': 'Recon',
            'Recon-HostDiscovery': 'Recon',
            'DNS_Spoofing': 'Spoofing',
            'MITM-ArpSpoofing': 'Spoofing',
            'BenignTraffic': 'Benign',
            'BrowserHijacking': 'Web',
            'Backdoor_Malware': 'Web',
            'XSS': 'Web',
            'Uploading_Attack': 'Web',
            'SqlInjection': 'Web',
            'CommandInjection': 'Web',
            'DictionaryBruteForce': 'BruteForce'
        }
        
        self.df = None
        self.model = None
        self.scaler = StandardScaler()
        self.camera_stats = None
        
        self.setup_ui()
    
    def setup_ui(self):
        # Configure styles
        style = ttk.Style()
        style.theme_use('clam')
        
        # Custom styles
        style.configure('Title.TLabel',
                       background=self.colors['bg'],
                       foreground=self.colors['accent'],
                       font=('Segoe UI', 24, 'bold'))
        
        style.configure('Card.TFrame',
                       background=self.colors['card'],
                       relief='flat')
        
        style.configure('Modern.TButton',
                       background=self.colors['accent'],
                       foreground='white',
                       borderwidth=0,
                       focuscolor='none',
                       font=('Segoe UI', 10, 'bold'),
                       padding=10)
        
        style.map('Modern.TButton',
                 background=[('active', self.colors['hover'])])
        
        style.configure('Status.TLabel',
                       background=self.colors['card'],
                       foreground=self.colors['fg'],
                       font=('Segoe UI', 10))
        
        # Main container
        main_container = tk.Frame(self.root, bg=self.colors['bg'])
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Header
        header_frame = tk.Frame(main_container, bg=self.colors['bg'])
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        title_label = ttk.Label(header_frame,
                               text="🛡️ Detektor Mrežnih Napada",
                               style='Title.TLabel')
        title_label.pack(side=tk.LEFT)
        
        subtitle = tk.Label(header_frame,
                           text="AI Forenzička Analiza Kamera i Mreže",
                           bg=self.colors['bg'],
                           fg=self.colors['fg'],
                           font=('Segoe UI', 11))
        subtitle.pack(side=tk.LEFT, padx=15, pady=8)
        
        # Control panel
        control_card = tk.Frame(main_container, bg=self.colors['card'],
                               relief='flat', bd=0)
        control_card.pack(fill=tk.X, pady=(0, 15))
        
        control_inner = tk.Frame(control_card, bg=self.colors['card'])
        control_inner.pack(padx=20, pady=20)
        
        buttons_data = [
            ("📁 Učitaj CSV", self.load_csv, self.colors['accent']),
            ("🤖 Treniraj Model", self.train_model, self.colors['success']),
            ("🔍 Analiziraj Saobraćaj", self.analyze_traffic, self.colors['warning']),
            ("📄 Generiši Izveštaj", self.generate_forensic_report, self.colors['danger'])
        ]
        
        for i, (text, command, color) in enumerate(buttons_data):
            btn = tk.Button(control_inner,
                          text=text,
                          command=command,
                          bg=color,
                          fg='white',
                          font=('Segoe UI', 10, 'bold'),
                          relief='flat',
                          cursor='hand2',
                          padx=20,
                          pady=12,
                          activebackground=self.colors['hover'])
            btn.grid(row=0, column=i, padx=8)
            
            # Hover effects
            btn.bind('<Enter>', lambda e, b=btn, c=color: b.configure(bg=self._lighten_color(c)))
            btn.bind('<Leave>', lambda e, b=btn, c=color: b.configure(bg=c))
        
        # Status bar
        status_card = tk.Frame(main_container, bg=self.colors['card'], relief='flat')
        status_card.pack(fill=tk.X, pady=(0, 15))
        
        status_inner = tk.Frame(status_card, bg=self.colors['card'])
        status_inner.pack(padx=20, pady=15, fill=tk.X)
        
        status_icon = tk.Label(status_inner,
                              text="📊",
                              bg=self.colors['card'],
                              fg=self.colors['fg'],
                              font=('Segoe UI', 14))
        status_icon.pack(side=tk.LEFT, padx=(0, 10))
        
        self.status_label = tk.Label(status_inner,
                                     text="Spremno za analizu mrežnog saobraćaja i detekciju kamera",
                                     bg=self.colors['card'],
                                     fg=self.colors['fg'],
                                     font=('Segoe UI', 11))
        self.status_label.pack(side=tk.LEFT)
        
        # Content area
        content_frame = tk.Frame(main_container, bg=self.colors['bg'])
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Results panel
        results_card = tk.Frame(content_frame, bg=self.colors['card'], relief='flat')
        results_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        results_header = tk.Label(results_card,
                                 text="📋 Rezultati Analize",
                                 bg=self.colors['card'],
                                 fg=self.colors['accent'],
                                 font=('Segoe UI', 13, 'bold'))
        results_header.pack(padx=20, pady=(20, 10), anchor='w')
        
        text_frame = tk.Frame(results_card, bg=self.colors['card'])
        text_frame.pack(padx=20, pady=(0, 20), fill=tk.BOTH, expand=True)
        
        self.results_text = scrolledtext.ScrolledText(text_frame,
                                                      width=55,
                                                      height=25,
                                                      bg=self.colors['bg'],
                                                      fg=self.colors['fg'],
                                                      font=('Consolas', 10),
                                                      relief='flat',
                                                      borderwidth=0,
                                                      insertbackground=self.colors['accent'])
        self.results_text.pack(fill=tk.BOTH, expand=True)
        
        # Visualization panel
        viz_card = tk.Frame(content_frame, bg=self.colors['card'], relief='flat')
        viz_card.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        viz_header = tk.Label(viz_card,
                             text="📊 Analiza Saobraćaja Kamera",
                             bg=self.colors['card'],
                             fg=self.colors['accent'],
                             font=('Segoe UI', 13, 'bold'))
        viz_header.pack(padx=20, pady=(20, 10), anchor='w')
        
        viz_inner = tk.Frame(viz_card, bg=self.colors['card'])
        viz_inner.pack(padx=20, pady=(0, 20), fill=tk.BOTH, expand=True)
        
        # Set dark theme for matplotlib
        plt.style.use('dark_background')
        self.fig, self.ax = plt.subplots(figsize=(7, 6), facecolor=self.colors['card'])
        self.ax.set_facecolor(self.colors['bg'])
        
        self.canvas = FigureCanvasTkAgg(self.fig, master=viz_inner)
        self.canvas.get_tk_widget().configure(bg=self.colors['card'])
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def _lighten_color(self, hex_color):
        """Lighten a hex color by 10%"""
        hex_color = hex_color.lstrip('#')
        rgb = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        rgb = tuple(min(255, int(c * 1.1)) for c in rgb)
        return f'#{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}'
    
    def load_csv(self):
        file_path = filedialog.askopenfilename(
            title="Izaberite CSV Fajl",
            filetypes=[("CSV fajlovi", "*.csv"), ("Svi fajlovi", "*.*")]
        )
        
        if file_path:
            try:
                self.df = pd.read_csv(file_path)
                self.status_label.config(
                    text=f"✓ Učitano {len(self.df):,} redova iz {os.path.basename(file_path)}"
                )
                
                self.results_text.insert(tk.END, f"{'='*60}\n")
                self.results_text.insert(tk.END, f"✓ Fajl učitan: {os.path.basename(file_path)}\n")
                self.results_text.insert(tk.END, f"  Redovi: {len(self.df):,}\n")
                self.results_text.insert(tk.END, f"  Kolone: {len(self.df.columns)}\n")
                self.results_text.insert(tk.END, f"{'='*60}\n\n")
                
            except Exception as e:
                messagebox.showerror("Greška", f"Neuspelo učitavanje fajla:\n{str(e)}")
    
    def train_model(self):
        if self.df is None:
            messagebox.showwarning("Upozorenje", "Molimo prvo učitajte CSV fajl!")
            return
        
        try:
            if 'label' in self.df.columns:
                self.df['attack_category'] = self.df['label'].map(self.dict_7classes)
                
                available_cols = [col for col in self.X_columns if col in self.df.columns]
                X = self.df[available_cols].fillna(0)
                y = self.df['attack_category']
                
                X_scaled = self.scaler.fit_transform(X)
                
                self.model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
                self.model.fit(X_scaled, y)
                
                self.status_label.config(text="✓ Model uspešno treniran!")
                
                self.results_text.insert(tk.END, "🤖 Treniranje Modela Završeno\n")
                self.results_text.insert(tk.END, f"  Karakteristike: {len(available_cols)}\n")
                self.results_text.insert(tk.END, f"  Klase: {', '.join(y.unique())}\n\n")
            else:
                messagebox.showwarning("Upozorenje", "CSV ne sadrži kolonu 'label'!")
                
        except Exception as e:
            messagebox.showerror("Greška", f"Treniranje neuspelo:\n{str(e)}")
    def detect_camera_traffic(self):
        try:
            camera_score = pd.Series(0, index=self.df.index)
            
            # Obrazac 1: Visoka konstantna brzina (video streaming) - Težina: 2
            if 'Rate' in self.df.columns:
                rate_mean = self.df['Rate'].mean()
                rate_std = self.df['Rate'].std()
                if rate_std > 0:
                    high_rate = self.df['Rate'] > (rate_mean + 0.5 * rate_std)
                    camera_score = camera_score + high_rate.astype(int) * 2
            
            # Obrazac 2: Veliki paketi (video podaci) - Težina: 2
            if 'Tot size' in self.df.columns:
                large_packets = self.df['Tot size'] > self.df['Tot size'].quantile(0.75)
                camera_score = camera_score + large_packets.astype(int) * 2
            
            # Obrazac 3: Nizak IAT - kontinuirani stream - Težina: 2
            if 'IAT' in self.df.columns:
                low_iat = self.df['IAT'] < self.df['IAT'].quantile(0.3)
                camera_score = camera_score + low_iat.astype(int) * 2
            
            # Obrazac 4: Intenzivan UDP saobraćaj (RTSP streaming) - Težina: 3
            if 'UDP' in self.df.columns:
                udp_heavy = self.df['UDP'] > 0.6
                camera_score = camera_score + udp_heavy.astype(int) * 3
            
            # Obrazac 5: HTTP/HTTPS za web interfejs - Težina: 1
            if 'HTTP' in self.df.columns and 'HTTPS' in self.df.columns:
                web_interface = (self.df['HTTP'] > 0) | (self.df['HTTPS'] > 0)
                camera_score = camera_score + web_interface.astype(int) * 1
            
            # Obrazac 6: Konzistentno trajanje toka - Težina: 1
            if 'Duration' in self.df.columns:
                long_duration = self.df['Duration'] > self.df['Duration'].quantile(0.6)
                camera_score = camera_score + long_duration.astype(int) * 1
            
            # Obrazac 7: Niska varijansa u vremenskim razmacima (stabilan stream) - Težina: 2
            if 'Std' in self.df.columns:
                low_variance = self.df['Std'] < self.df['Std'].quantile(0.4)
                camera_score = camera_score + low_variance.astype(int) * 2
            
            # Obrazac 8: Visoka prosečna veličina paketa - Težina: 1
            if 'AVG' in self.df.columns:
                high_avg = self.df['AVG'] > self.df['AVG'].quantile(0.7)
                camera_score = camera_score + high_avg.astype(int) * 1
            
            # Klasifikuj kao kameru ako je skor >= 6 (od maksimalnih 14)
            self.df['is_camera_traffic'] = camera_score >= 6
            self.df['camera_confidence_score'] = camera_score
            
            camera_count = int(self.df['is_camera_traffic'].sum())
            camera_percentage = (camera_count / len(self.df)) * 100 if len(self.df) > 0 else 0
            
            # Izračunaj statistiku kamera
            if camera_count > 0:
                avg_confidence = float(self.df[self.df['is_camera_traffic']]['camera_confidence_score'].mean())
            else:
                avg_confidence = 0
            
            self.camera_stats = {
                'total_flows': camera_count,
                'percentage': camera_percentage,
                'avg_confidence': avg_confidence
            }
            
            # Dodaj rezultate detekcije kamera u izlaz
            self.results_text.insert(tk.END, f"\n{'='*60}\n")
            self.results_text.insert(tk.END, "🎥 DETEKCIJA SAOBRAĆAJA KAMERA\n")
            self.results_text.insert(tk.END, f"{'='*60}\n\n")
            
            self.results_text.insert(tk.END, f"Detektovan saobraćaj kamera: {camera_count:,} tokova ({camera_percentage:.2f}%)\n")
            
            if camera_count > 0:
                self.results_text.insert(tk.END, f"Prosečan skor pouzdanosti: {avg_confidence:.1f}/14\n\n")
                
                # Distribucija protokola za saobraćaj kamera
                if 'UDP' in self.df.columns:
                    camera_udp = float(self.df[self.df['is_camera_traffic']]['UDP'].mean())
                    self.results_text.insert(tk.END, f"UDP korišćenje: {camera_udp*100:.1f}%\n")
                
                if 'Rate' in self.df.columns:
                    avg_rate = float(self.df[self.df['is_camera_traffic']]['Rate'].mean())
                    self.results_text.insert(tk.END, f"Prosečna brzina prenosa: {avg_rate:.2f}\n")
                
                if 'Tot size' in self.df.columns:
                    avg_size = float(self.df[self.df['is_camera_traffic']]['Tot size'].mean())
                    self.results_text.insert(tk.END, f"Prosečna veličina paketa: {avg_size:.2f}\n")
                
                # Proveri korelaciju sa napadima
                if 'predicted_attack' in self.df.columns:
                    camera_attacks = self.df[self.df['is_camera_traffic']]['predicted_attack'].value_counts()
                    self.results_text.insert(tk.END, f"\nNapadi na saobraćaj kamera:\n")
                    for attack, count in camera_attacks.items():
                        attack_pct = (count / camera_count) * 100
                        self.results_text.insert(tk.END, f"  {attack}: {count:,} ({attack_pct:.1f}%)\n")
                    
                    if 'Mirai' in camera_attacks.index:
                        mirai_on_cameras = int(camera_attacks['Mirai'])
                        self.results_text.insert(tk.END, f"\n⚠️ UPOZORENJE: {mirai_on_cameras:,} Mirai napada na kamere!\n")
            else:
                self.results_text.insert(tk.END, "Nisu detektovani obrasci saobraćaja kamera.\n")
            
            self.results_text.insert(tk.END, f"\n{'='*60}\n\n")
            
        except Exception as e:
            self.results_text.insert(tk.END, f"⚠️ Greška pri detekciji kamera: {str(e)}\n\n")
    
    def analyze_traffic(self):
        if self.df is None:
            messagebox.showwarning("Upozorenje", "Molimo prvo učitajte CSV fajl!")
            return
        
        if self.model is None:
            messagebox.showwarning("Upozorenje", "Molimo prvo trenirajte model!")
            return
        
        try:
            available_cols = [col for col in self.X_columns if col in self.df.columns]
            X = self.df[available_cols].fillna(0)
            X_scaled = self.scaler.transform(X)
            
            predictions = self.model.predict(X_scaled)
            self.df['predicted_attack'] = predictions
            
            # Detektuj saobraćaj kamera
            self.detect_camera_traffic()
            
            # Vizualizacija - Raspodela saobraćaja kamera
            self.ax.clear()
            
            if self.camera_stats and self.camera_stats['total_flows'] > 0:
                # Prikaži saobraćaj kamera vs napadi na kamere
                camera_df = self.df[self.df['is_camera_traffic'] == True]
                attack_on_cameras = camera_df['predicted_attack'].value_counts()
                
                categories = list(attack_on_cameras.keys())
                counts = attack_on_cameras.tolist()
                
                # Mapiranje boja
                color_map = {
                    'DDoS': '#f38ba8',
                    'DoS': '#fab387',
                    'Mirai': '#f9e2af',
                    'Recon': '#a6e3a1',
                    'Web': '#94e2d5',
                    'Spoofing': '#89b4fa',
                    'BruteForce': '#cba6f7',
                    'Benign': '#b4befe'
                }
                
                bar_colors = [color_map.get(cat, '#ff6b9d') for cat in categories]
                
                bars = self.ax.barh(categories, counts, color=bar_colors, 
                                   edgecolor='white', linewidth=1.5)
                
                for bar, count, category in zip(bars, counts, categories):
                    width = bar.get_width()
                    percentage = (count / self.camera_stats['total_flows']) * 100
                    self.ax.text(width, bar.get_y() + bar.get_height()/2,
                               f' {count:,} ({percentage:.1f}%)',
                               ha='left', va='center', fontsize=10,
                               weight='bold', color='white')
                
                self.ax.set_xlabel('Broj Tokova Kamera', fontsize=11, 
                                  weight='bold', color='white')
                self.ax.set_ylabel('Tip Saobraćaja', fontsize=11, 
                                  weight='bold', color='white')
                self.ax.set_title(f'Analiza Saobraćaja Kamera ({self.camera_stats["total_flows"]:,} tokova detektovano)',
                                fontsize=12, weight='bold', pad=20, color='white')
                
                self.ax.grid(axis='x', alpha=0.2, linestyle='--', color='white')
                self.ax.tick_params(colors='white')
            else:
                self.ax.text(0.5, 0.5, 'Saobraćaj Kamera Nije Detektovan',
                           ha='center', va='center', fontsize=14,
                           color='white', transform=self.ax.transAxes)
                self.ax.set_xlim(0, 1)
                self.ax.set_ylim(0, 1)
                self.ax.axis('off')
            
            self.fig.tight_layout()
            self.canvas.draw()
            
            # Ažuriraj status sa informacijama o kamerama
            if self.camera_stats and self.camera_stats['total_flows'] > 0:
                self.status_label.config(
                    text=f"✓ Analizirano {len(predictions):,} tokova | 🎥 Detektovano {self.camera_stats['total_flows']:,} tokova kamera ({self.camera_stats['percentage']:.1f}%)"
                )
            else:
                self.status_label.config(text=f"✓ Analizirano {len(predictions):,} tokova | Saobraćaj kamera nije detektovan")
            
        except Exception as e:
            messagebox.showerror("Greška", f"Analiza neuspela:\n{str(e)}")
    
    def generate_forensic_report(self):
        if self.df is None or 'predicted_attack' not in self.df.columns:
            messagebox.showwarning("Upozorenje", "Molimo prvo analizirajte saobraćaj!")
            return
        
        try:
            report_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Tekstualni fajlovi", "*.txt"), ("Svi fajlovi", "*.*")],
                initialfile=f"forenzicki_izvestaj_kamera_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            )
            
            if not report_path:
                return
            
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write(" FORENZIČKI IZVEŠTAJ ANALIZE SAOBRAĆAJA KAMERA\n")
                f.write("=" * 80 + "\n\n")
                
                f.write(f"Izveštaj Generisan: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Ukupno Analiziranih Paketa: {len(self.df):,}\n\n")
                
                # Sekcija detekcije kamera
                if 'is_camera_traffic' in self.df.columns:
                    f.write("-" * 80 + "\n")
                    f.write("REZIME DETEKCIJE SAOBRAĆAJA KAMERA\n")
                    f.write("-" * 80 + "\n\n")
                    
                    camera_count = self.df['is_camera_traffic'].sum()
                    camera_percentage = (camera_count / len(self.df)) * 100
                    non_camera_count = len(self.df) - camera_count
                    
                    f.write(f"Tokovi Saobraćaja Kamera: {camera_count:,} ({camera_percentage:.2f}%)\n")
                    f.write(f"Tokovi Koji Nisu Kamere: {non_camera_count:,} ({100-camera_percentage:.2f}%)\n\n")
                    
                    if camera_count > 0:
                        avg_conf = self.df[self.df['is_camera_traffic']]['camera_confidence_score'].mean()
                        f.write(f"Prosečna Pouzdanost Detekcije: {avg_conf:.1f}/14\n\n")
                        
                        f.write("Metodologija Detekcije:\n")
                        f.write(" • Visoka konstantna brzina prenosa (obrazac video streaminga)\n")
                        f.write(" • Veliki paketi (video podaci)\n")
                        f.write(" • Nizak vremenski razmak između paketa (kontinuirani stream)\n")
                        f.write(" • Intenzivan UDP saobraćaj (RTSP protokol)\n")
                        f.write(" • Prisustvo HTTP/HTTPS (web interfejs kamere)\n")
                        f.write(" • Konzistentno trajanje toka\n")
                        f.write(" • Niska varijansa u vremenskim razmacima (stabilan stream)\n")
                        f.write(" • Visoka prosečna veličina paketa\n\n")
                        
                        # Karakteristike saobraćaja kamera
                        camera_df = self.df[self.df['is_camera_traffic'] == True]
                        
                        f.write("-" * 80 + "\n")
                        f.write("KARAKTERISTIKE SAOBRAĆAJA KAMERA\n")
                        f.write("-" * 80 + "\n\n")
                        
                        if 'Rate' in camera_df.columns:
                            f.write(f"Prosečna Brzina Prenosa: {camera_df['Rate'].mean():.2f}\n")
                            f.write(f"Maksimalna Brzina Prenosa: {camera_df['Rate'].max():.2f}\n")
                            f.write(f"Minimalna Brzina Prenosa: {camera_df['Rate'].min():.2f}\n\n")
                        
                        if 'Tot size' in camera_df.columns:
                            f.write(f"Prosečna Veličina Paketa: {camera_df['Tot size'].mean():.2f} bajtova\n")
                            f.write(f"Ukupna Zapremina Podataka: {camera_df['Tot size'].sum():.2f} bajtova\n\n")
                        
                        if 'UDP' in camera_df.columns:
                            udp_pct = camera_df['UDP'].mean() * 100
                            f.write(f"Korišćenje UDP Protokola: {udp_pct:.1f}%\n\n")
                        
                        # Napadi na kamere
                        if 'predicted_attack' in camera_df.columns:
                            f.write("-" * 80 + "\n")
                            f.write("DETEKTOVANI NAPADI NA SAOBRAĆAJ KAMERA\n")
                            f.write("-" * 80 + "\n\n")
                            
                            camera_attacks = camera_df['predicted_attack'].value_counts()
                            
                            for attack, count in camera_attacks.items():
                                attack_pct = (count / camera_count) * 100
                                f.write(f"{attack:20s}: {count:8,d} tokova ({attack_pct:6.2f}%)\n")
                            
                            f.write("\n")
                            
                            # Detaljna analiza napada na kamere
                            f.write("-" * 80 + "\n")
                            f.write("DETALJNA ANALIZA NAPADA NA KAMERE\n")
                            f.write("-" * 80 + "\n\n")
                            
                            for attack_type in camera_attacks.keys():
                                if attack_type == 'Benign':
                                    continue
                                
                                f.write(f"\n### {attack_type} na Saobraćaj Kamera ###\n")
                                attack_camera_df = camera_df[camera_df['predicted_attack'] == attack_type]
                                
                                if 'Rate' in attack_camera_df.columns:
                                    f.write(f"  Prosečna Brzina: {attack_camera_df['Rate'].mean():.2f}\n")
                                if 'Duration' in attack_camera_df.columns:
                                    f.write(f"  Prosečno Trajanje: {attack_camera_df['Duration'].mean():.2f}\n")
                                if 'Tot size' in attack_camera_df.columns:
                                    f.write(f"  Prosečna Veličina Paketa: {attack_camera_df['Tot size'].mean():.2f}\n")
                            
                            f.write("\n" + "-" * 80 + "\n")
                            f.write("PREPORUKE ZA BEZBEDNOST KAMERA\n")
                            f.write("-" * 80 + "\n\n")
                            
                            f.write("🎥 HITNE AKCIJE ZA BEZBEDNOST KAMERA:\n\n")
                            
                            f.write("1. IZOLACIJA MREŽE:\n")
                            f.write("   - Postavite sve kamere u poseban VLAN\n")
                            f.write("   - Implementirajte striktna firewall pravila\n")
                            f.write("   - Onemogućite pristup internetu za kamere ako je moguće\n\n")
                            
                            f.write("2. KONTROLA PRISTUPA:\n")
                            f.write("   - Odmah promenite SVE podrazumevane lozinke\n")
                            f.write("   - Koristite jake, jedinstvene lozinke za svaku kameru\n")
                            f.write("   - Omogućite dvofaktorsku autentifikaciju gde je dostupno\n")
                            f.write("   - Implementirajte MAC adresno filtriranje\n\n")
                            
                            f.write("3. FIRMWARE I AŽURIRANJA:\n")
                            f.write("   - Ažurirajte firmware kamera na najnoviju verziju\n")
                            f.write("   - Omogućite automatska bezbednosna ažuriranja\n")
                            f.write("   - Redovno proveravajte bezbednosne biltene proizvođača\n\n")
                            
                            f.write("4. POJAČAVANJE FUNKCIONALNOSTI:\n")
                            f.write("   - Onemogućite UPnP na svim kamerama\n")
                            f.write("   - Onemogućite nekorišćene funkcije i portove\n")
                            f.write("   - Isključite cloud servise ako nisu potrebni\n")
                            f.write("   - Onemogućite P2P konekcije\n\n")
                            
                            f.write("5. DALJINSKI PRISTUP:\n")
                            f.write("   - Koristite VPN za sve daljinske pristupe kamerama\n")
                            f.write("   - Nikada ne izlažite kamere direktno internetu\n")
                            f.write("   - Implementirajte IP whitelist\n\n")
                            
                            f.write("6. PRAĆENJE:\n")
                            f.write("   - Omogućite logovanje pristupa kamerama\n")
                            f.write("   - Pratite neobične obrasce saobraćaja\n")
                            f.write("   - Postavite upozorenja za neovlašćene pokušaje pristupa\n")
                            f.write("   - Redovne bezbednosne revizije\n\n")
                            
                            # Mirai-specifične preporuke
                            if 'Mirai' in camera_attacks.index:
                                mirai_count = camera_attacks['Mirai']
                                f.write("⚠️ KRITIČNO: DETEKTOVANA MIRAI BOTNET AKTIVNOST\n\n")
                                f.write(f"Mirai napadi na kamere: {mirai_count:,} tokova\n\n")
                                
                                f.write("HITNI KORACI ZA UBLAŽAVANJE MIRAI PRETNJE:\n")
                                f.write("   - Odmah izolovati pogođene kamere\n")
                                f.write("   - Resetovati sve potencijalno kompromitovane kamere na fabričke\n")
                                f.write("   - Skenirati celu mrežu za botnet aktivnost\n")
                                f.write("   - Blokirati uobičajene Mirai C&C server portove (23, 2323, 48101)\n")
                                f.write("   - Pratiti aktivnost skeniranja na portovima 23, 2323\n")
                                f.write("   - Razmotriti zamenu kamera sa bezbednijim modelima\n\n")
                            
                            f.write("-" * 80 + "\n")
                            f.write("PRIORITETNA VREMENSKA LINIJA AKCIJA\n")
                            f.write("-" * 80 + "\n\n")
                            
                            f.write("HITNO (Sledećih 24 sata):\n")
                            f.write("   ✓ Promeniti sve lozinke kamera\n")
                            f.write("   ✓ Izolirati mrežu kamera\n")
                            f.write("   ✓ Onemogućiti UPnP i nekorišćene funkcije\n")
                            f.write("   ✓ Pregledati logove pristupa za sumnjive aktivnosti\n\n")
                            
                            f.write("KRATKOROČNO (Sledeća nedelja):\n")
                            f.write("   ✓ Ažurirati sav firmware kamera\n")
                            f.write("   ✓ Implementirati VLAN separaciju\n")
                            f.write("   ✓ Konfigurisati VPN za daljinski pristup\n")
                            f.write("   ✓ Omogućiti logovanje i praćenje\n\n")
                            
                            f.write("DUGOROČNO (Sledeći mesec):\n")
                            f.write("   ✓ Sprovesti potpunu bezbednosnu reviziju\n")
                            f.write("   ✓ Implementirati IDS/IPS za mrežu kamera\n")
                            f.write("   ✓ Redovno penetraciono testiranje\n")
                            f.write("   ✓ Obuka osoblja o bezbednosnoj svesti\n")
                            f.write("   ✓ Pregledati i ažurirati politiku bezbednosti kamera\n\n")
                    else:
                        f.write("Saobraćaj kamera nije detektovan u analiziranim podacima.\n\n")
                
                f.write("\n" + "=" * 80 + "\n")
                f.write("KRAJ IZVEŠTAJA\n")
                f.write("=" * 80 + "\n")
            
            self.results_text.insert(tk.END, f"✓ Forenzički izveštaj kamera sačuvan: {os.path.basename(report_path)}\n\n")
            messagebox.showinfo("Uspeh", f"Forenzički izveštaj kamera sačuvan na:\n{report_path}")
            
        except Exception as e:
            messagebox.showerror("Greška", f"Generisanje izveštaja neuspelo:\n{str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkForensicApp(root)
    root.mainloop()