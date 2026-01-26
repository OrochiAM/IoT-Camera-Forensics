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
        self.root.title("🛡️ Network Attack Detector & Forensic Reporter")
        self.root.geometry("1400x900")
        
        # Modern color scheme
        self.colors = {
            'bg': '#1e1e2e',
            'fg': '#cdd6f4',
            'accent': '#89b4fa',
            'success': '#a6e3a1',
            'warning': '#f9e2af',
            'danger': '#f38ba8',
            'card': '#313244',
            'hover': '#45475a'
        }
        
        self.root.configure(bg=self.colors['bg'])
        
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
                            text="🛡️ Network Attack Detector",
                            style='Title.TLabel')
        title_label.pack(side=tk.LEFT)
        
        subtitle = tk.Label(header_frame,
                        text="AI Analiza Kamere",
                        bg=self.colors['bg'],
                        fg=self.colors['fg'],
                        font=('Segoe UI', 11))
        subtitle.pack(side=tk.LEFT, padx=15, pady=8)
        
        # Control panel
        control_card = tk.Frame(main_container, bg=self.colors['card'], relief='flat', bd=0)
        control_card.pack(fill=tk.X, pady=(0, 15))
        
        control_inner = tk.Frame(control_card, bg=self.colors['card'])
        control_inner.pack(padx=20, pady=20)
        
        buttons_data = [
            ("📁 Load CSV", self.load_csv, self.colors['accent']),
            ("🤖 Train Model", self.train_model, self.colors['success']),
            ("🔍 Analyze Traffic", self.analyze_traffic, self.colors['warning']),
            ("📄 Generate Report", self.generate_forensic_report, self.colors['danger'])
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
                                    text="Ready to analyze network traffic",
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
                                text="📋 Analysis Results",
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
                            text="📊 Attack Distribution",
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
            title="Select CSV File",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                self.df = pd.read_csv(file_path)
                self.status_label.config(
                    text=f"✓ Loaded {len(self.df):,} rows from {os.path.basename(file_path)}"
                )
                self.results_text.insert(tk.END, f"{'='*60}\n")
                self.results_text.insert(tk.END, f"✓ File loaded: {os.path.basename(file_path)}\n")
                self.results_text.insert(tk.END, f"  Rows: {len(self.df):,}\n")
                self.results_text.insert(tk.END, f"  Columns: {len(self.df.columns)}\n")
                self.results_text.insert(tk.END, f"{'='*60}\n\n")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file:\n{str(e)}")
                
    def train_model(self):
        if self.df is None:
            messagebox.showwarning("Warning", "Please load a CSV file first!")
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
                
                self.status_label.config(text="✓ Model trained successfully!")
                self.results_text.insert(tk.END, "🤖 Model Training Complete\n")
                self.results_text.insert(tk.END, f"   Features: {len(available_cols)}\n")
                self.results_text.insert(tk.END, f"   Classes: {', '.join(y.unique())}\n\n")
            else:
                messagebox.showwarning("Warning", "CSV doesn't contain 'label' column!")
                
        except Exception as e:
            messagebox.showerror("Error", f"Training failed:\n{str(e)}")
            
    def analyze_traffic(self):
        if self.df is None:
            messagebox.showwarning("Warning", "Please load a CSV file first!")
            return
            
        if self.model is None:
            messagebox.showwarning("Warning", "Please train the model first!")
            return
            
        try:
            available_cols = [col for col in self.X_columns if col in self.df.columns]
            X = self.df[available_cols].fillna(0)
            X_scaled = self.scaler.transform(X)
            
            predictions = self.model.predict(X_scaled)
            self.df['predicted_attack'] = predictions
            
            attack_counts = Counter(predictions)
            
            self.results_text.insert(tk.END, f"\n{'='*60}\n")
            self.results_text.insert(tk.END, "🔍 NETWORK TRAFFIC ANALYSIS\n")
            self.results_text.insert(tk.END, f"{'='*60}\n\n")
            
            for attack_type, count in attack_counts.most_common():
                percentage = (count / len(predictions)) * 100
                bar = '█' * int(percentage / 2)
                self.results_text.insert(tk.END, 
                    f"{attack_type:12s} │{bar:50s}│ {count:6,d} ({percentage:5.2f}%)\n")
            
            self.results_text.insert(tk.END, f"{'='*60}\n\n")
            
            # Visualization
            self.ax.clear()
            sorted_data = sorted(zip(attack_counts.keys(), attack_counts.values()), 
                            key=lambda x: x[1], reverse=True)
            attack_types = [x[0] for x in sorted_data]
            counts = [x[1] for x in sorted_data]
            
            colors = ['#f38ba8', '#fab387', '#f9e2af', '#a6e3a1', 
                    '#94e2d5', '#89b4fa', '#cba6f7'][:len(attack_types)]
            
            bars = self.ax.barh(attack_types, counts, color=colors, 
                            edgecolor='white', linewidth=1.5)
            
            for bar, count in zip(bars, counts):
                width = bar.get_width()
                percentage = (count / len(predictions)) * 100
                self.ax.text(width, bar.get_y() + bar.get_height()/2, 
                        f'  {count:,} ({percentage:.1f}%)',
                        ha='left', va='center', fontsize=10, 
                        weight='bold', color='white')
            
            self.ax.set_xlabel('Detected Packets', fontsize=11, weight='bold', color='white')
            self.ax.set_ylabel('Attack Type', fontsize=11, weight='bold', color='white')
            self.ax.set_title('Attack Distribution Analysis', 
                            fontsize=13, weight='bold', pad=20, color='white')
            self.ax.grid(axis='x', alpha=0.2, linestyle='--', color='white')
            self.ax.tick_params(colors='white')
            
            self.fig.tight_layout()
            self.canvas.draw()
            
            self.status_label.config(text=f"✓ Analyzed {len(predictions):,} network flows")
            
        except Exception as e:
            messagebox.showerror("Error", f"Analysis failed:\n{str(e)}")
            
    def generate_forensic_report(self):
        if self.df is None or 'predicted_attack' not in self.df.columns:
            messagebox.showwarning("Warning", "Please analyze traffic first!")
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
                f.write("       NETWORK FORENSIC ANALYSIS REPORT\n")
                f.write("=" * 80 + "\n\n")
                
                f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Packets Analyzed: {len(self.df):,}\n\n")
                
                f.write("-" * 80 + "\n")
                f.write("ATTACK DETECTION STATISTICS\n")
                f.write("-" * 80 + "\n\n")
                
                attack_counts = Counter(self.df['predicted_attack'])
                for attack_type, count in attack_counts.most_common():
                    percentage = (count / len(self.df)) * 100
                    f.write(f"{attack_type:20s}: {count:8,d} packets ({percentage:6.2f}%)\n")
                
                f.write("\n" + "-" * 80 + "\n")
                f.write("DETAILED ATTACK ANALYSIS\n")
                f.write("-" * 80 + "\n\n")
                
                for attack_type in attack_counts.keys():
                    if attack_type == 'Benign':
                        continue
                        
                    f.write(f"\n### {attack_type} ###\n")
                    attack_df = self.df[self.df['predicted_attack'] == attack_type]
                    
                    if 'Protocol Type' in attack_df.columns:
                        protocols = attack_df['Protocol Type'].value_counts()
                        f.write(f"  Protocols: {dict(protocols)}\n")
                    
                    if 'Rate' in attack_df.columns:
                        f.write(f"  Average Rate: {attack_df['Rate'].mean():.2f}\n")
                    
                    if 'Duration' in attack_df.columns:
                        f.write(f"  Average Duration: {attack_df['Duration'].mean():.2f}\n")
                    
                f.write("\n" + "-" * 80 + "\n")
                f.write("SECURITY RECOMMENDATIONS\n")
                f.write("-" * 80 + "\n\n")
                
                if attack_counts.get('DDoS', 0) > 0:
                    f.write("• DDoS ATTACK DETECTED\n")
                    f.write("  - Implement rate limiting\n")
                    f.write("  - Use DDoS protection services\n")
                    f.write("  - Increase bandwidth capacity\n\n")
                
                if attack_counts.get('Recon', 0) > 0:
                    f.write("• RECONNAISSANCE ACTIVITIES DETECTED\n")
                    f.write("  - Enhance network activity monitoring\n")
                    f.write("  - Block port scanning\n")
                    f.write("  - Implement IDS/IPS systems\n\n")
                
                if attack_counts.get('Web', 0) > 0:
                    f.write("• WEB ATTACKS DETECTED\n")
                    f.write("  - Update web application firewalls\n")
                    f.write("  - Use input validation\n")
                    f.write("  - Implement WAF (Web Application Firewall)\n\n")
                
                f.write("\n" + "=" * 80 + "\n")
                f.write("END OF REPORT\n")
                f.write("=" * 80 + "\n")
            
            self.results_text.insert(tk.END, 
                f"✓ Forensic report saved: {os.path.basename(report_path)}\n\n")
            messagebox.showinfo("Success", f"Report saved to:\n{report_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Report generation failed:\n{str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkForensicApp(root)
    root.mainloop()