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
                            text="🛡️ Network Attack Detector",
                            style='Title.TLabel')
        title_label.pack(side=tk.LEFT)
        
        subtitle = tk.Label(header_frame,
                        text="AI-Powered Camera & Network Forensic Analysis",
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
                                    text="Ready to analyze network traffic and detect cameras",
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
                            text="📊 Camera Traffic Analysis",
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
    
    def detect_camera_traffic(self):
        try:
            camera_score = pd.Series(0, index=self.df.index)
            
            # Pattern 1: High constant rate (video streaming) - Weight: 2
            if 'Rate' in self.df.columns:
                rate_mean = self.df['Rate'].mean()
                rate_std = self.df['Rate'].std()
                if rate_std > 0:
                    high_rate = self.df['Rate'] > (rate_mean + 0.5 * rate_std)
                    camera_score = camera_score + high_rate.astype(int) * 2
            
            # Pattern 2: Large packet sizes (video data) - Weight: 2
            if 'Tot size' in self.df.columns:
                large_packets = self.df['Tot size'] > self.df['Tot size'].quantile(0.75)
                camera_score = camera_score + large_packets.astype(int) * 2
            
            # Pattern 3: Low IAT - continuous streaming - Weight: 2
            if 'IAT' in self.df.columns:
                low_iat = self.df['IAT'] < self.df['IAT'].quantile(0.3)
                camera_score = camera_score + low_iat.astype(int) * 2
            
            # Pattern 4: UDP heavy traffic (RTSP streaming) - Weight: 3
            if 'UDP' in self.df.columns:
                udp_heavy = self.df['UDP'] > 0.6
                camera_score = camera_score + udp_heavy.astype(int) * 3
            
            # Pattern 5: HTTP/HTTPS for web interface - Weight: 1
            if 'HTTP' in self.df.columns and 'HTTPS' in self.df.columns:
                web_interface = (self.df['HTTP'] > 0) | (self.df['HTTPS'] > 0)
                camera_score = camera_score + web_interface.astype(int) * 1
            
            # Pattern 6: Consistent flow duration - Weight: 1
            if 'Duration' in self.df.columns:
                long_duration = self.df['Duration'] > self.df['Duration'].quantile(0.6)
                camera_score = camera_score + long_duration.astype(int) * 1
            
            # Pattern 7: Low variance in packet timing (steady stream) - Weight: 2
            if 'Std' in self.df.columns:
                low_variance = self.df['Std'] < self.df['Std'].quantile(0.4)
                camera_score = camera_score + low_variance.astype(int) * 2
            
            # Pattern 8: High average packet size - Weight: 1
            if 'AVG' in self.df.columns:
                high_avg = self.df['AVG'] > self.df['AVG'].quantile(0.7)
                camera_score = camera_score + high_avg.astype(int) * 1
            
            # Classify as camera if score >= 6 (out of max 14)
            self.df['is_camera_traffic'] = camera_score >= 6
            self.df['camera_confidence_score'] = camera_score
            
            camera_count = int(self.df['is_camera_traffic'].sum())
            camera_percentage = (camera_count / len(self.df)) * 100 if len(self.df) > 0 else 0
            
            # Calculate camera statistics
            if camera_count > 0:
                avg_confidence = float(self.df[self.df['is_camera_traffic']]['camera_confidence_score'].mean())
            else:
                avg_confidence = 0
                
            self.camera_stats = {
                'total_flows': camera_count,
                'percentage': camera_percentage,
                'avg_confidence': avg_confidence
            }
            
            # Add camera detection results to output
            self.results_text.insert(tk.END, f"\n{'='*60}\n")
            self.results_text.insert(tk.END, "🎥 CAMERA TRAFFIC DETECTION\n")
            self.results_text.insert(tk.END, f"{'='*60}\n\n")
            self.results_text.insert(tk.END, f"Detected camera traffic: {camera_count:,} flows ({camera_percentage:.2f}%)\n")
            
            if camera_count > 0:
                self.results_text.insert(tk.END, f"Average confidence score: {avg_confidence:.1f}/14\n\n")
                
                # Protocol distribution for camera traffic
                if 'UDP' in self.df.columns:
                    camera_udp = float(self.df[self.df['is_camera_traffic']]['UDP'].mean())
                    self.results_text.insert(tk.END, f"UDP usage: {camera_udp*100:.1f}%\n")
                
                if 'Rate' in self.df.columns:
                    avg_rate = float(self.df[self.df['is_camera_traffic']]['Rate'].mean())
                    self.results_text.insert(tk.END, f"Average data rate: {avg_rate:.2f}\n")
                
                if 'Tot size' in self.df.columns:
                    avg_size = float(self.df[self.df['is_camera_traffic']]['Tot size'].mean())
                    self.results_text.insert(tk.END, f"Average packet size: {avg_size:.2f}\n")
                
                # Check correlation with attacks
                if 'predicted_attack' in self.df.columns:
                    camera_attacks = self.df[self.df['is_camera_traffic']]['predicted_attack'].value_counts()
                    self.results_text.insert(tk.END, f"\nAttacks on camera traffic:\n")
                    for attack, count in camera_attacks.items():
                        attack_pct = (count / camera_count) * 100
                        self.results_text.insert(tk.END, f"  {attack}: {count:,} ({attack_pct:.1f}%)\n")
                    
                    if 'Mirai' in camera_attacks.index:
                        mirai_on_cameras = int(camera_attacks['Mirai'])
                        self.results_text.insert(tk.END, 
                            f"\n⚠️  ALERT: {mirai_on_cameras:,} Mirai attacks on cameras!\n")
            else:
                self.results_text.insert(tk.END, "No camera traffic patterns detected.\n")
            
            self.results_text.insert(tk.END, f"\n{'='*60}\n\n")
            
        except Exception as e:
            self.results_text.insert(tk.END, f"⚠️  Camera detection error: {str(e)}\n\n")

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
            
            # Detect camera traffic
            self.detect_camera_traffic()
            
            # Visualization - Camera traffic breakdown
            self.ax.clear()
            
            if self.camera_stats and self.camera_stats['total_flows'] > 0:
                # Show camera traffic vs attacks on cameras
                camera_df = self.df[self.df['is_camera_traffic'] == True]
                attack_on_cameras = camera_df['predicted_attack'].value_counts()
                
                categories = list(attack_on_cameras.keys())
                counts = attack_on_cameras.tolist()
                
                # Color mapping
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
                            f'  {count:,} ({percentage:.1f}%)',
                            ha='left', va='center', fontsize=10, 
                            weight='bold', color='white')
                
                self.ax.set_xlabel('Number of Camera Flows', fontsize=11, weight='bold', color='white')
                self.ax.set_ylabel('Traffic Type', fontsize=11, weight='bold', color='white')
                self.ax.set_title(f'🎥 Camera Traffic Analysis ({self.camera_stats["total_flows"]:,} flows detected)', 
                                fontsize=12, weight='bold', pad=20, color='white')
                self.ax.grid(axis='x', alpha=0.2, linestyle='--', color='white')
                self.ax.tick_params(colors='white')
            else:
                self.ax.text(0.5, 0.5, 'No Camera Traffic Detected', 
                        ha='center', va='center', fontsize=14, color='white',
                        transform=self.ax.transAxes)
                self.ax.set_xlim(0, 1)
                self.ax.set_ylim(0, 1)
                self.ax.axis('off')
            
            self.fig.tight_layout()
            self.canvas.draw()
            
            # Update status with camera info
            if self.camera_stats and self.camera_stats['total_flows'] > 0:
                self.status_label.config(
                    text=f"✓ Analyzed {len(predictions):,} flows | 🎥 Detected {self.camera_stats['total_flows']:,} camera flows ({self.camera_stats['percentage']:.1f}%)"
                )
            else:
                self.status_label.config(text=f"✓ Analyzed {len(predictions):,} flows | No camera traffic detected")
            
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
                initialfile=f"camera_forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            )
            
            if not report_path:
                return
                
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("       CAMERA TRAFFIC FORENSIC ANALYSIS REPORT\n")
                f.write("=" * 80 + "\n\n")
                
                f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Packets Analyzed: {len(self.df):,}\n\n")
                
                # Camera Detection Section
                if 'is_camera_traffic' in self.df.columns:
                    f.write("-" * 80 + "\n")
                    f.write("CAMERA TRAFFIC DETECTION SUMMARY\n")
                    f.write("-" * 80 + "\n\n")
                    
                    camera_count = self.df['is_camera_traffic'].sum()
                    camera_percentage = (camera_count / len(self.df)) * 100
                    non_camera_count = len(self.df) - camera_count
                    
                    f.write(f"Camera Traffic Flows: {camera_count:,} ({camera_percentage:.2f}%)\n")
                    f.write(f"Non-Camera Traffic Flows: {non_camera_count:,} ({100-camera_percentage:.2f}%)\n\n")
                    
                    if camera_count > 0:
                        avg_conf = self.df[self.df['is_camera_traffic']]['camera_confidence_score'].mean()
                        f.write(f"Average Detection Confidence: {avg_conf:.1f}/14\n\n")
                        
                        f.write("Detection Methodology:\n")
                        f.write("  • High constant data rate (video streaming pattern)\n")
                        f.write("  • Large packet sizes (video data)\n")
                        f.write("  • Low inter-arrival time (continuous stream)\n")
                        f.write("  • UDP-heavy traffic (RTSP protocol)\n")
                        f.write("  • HTTP/HTTPS presence (camera web interface)\n")
                        f.write("  • Consistent flow duration\n")
                        f.write("  • Low variance in timing (steady stream)\n")
                        f.write("  • High average packet size\n\n")
                        
                        # Camera traffic characteristics
                        camera_df = self.df[self.df['is_camera_traffic'] == True]
                        
                        f.write("-" * 80 + "\n")
                        f.write("CAMERA TRAFFIC CHARACTERISTICS\n")
                        f.write("-" * 80 + "\n\n")
                        
                        if 'Rate' in camera_df.columns:
                            f.write(f"Average Data Rate: {camera_df['Rate'].mean():.2f}\n")
                            f.write(f"Max Data Rate: {camera_df['Rate'].max():.2f}\n")
                            f.write(f"Min Data Rate: {camera_df['Rate'].min():.2f}\n\n")
                        
                        if 'Tot size' in camera_df.columns:
                            f.write(f"Average Packet Size: {camera_df['Tot size'].mean():.2f} bytes\n")
                            f.write(f"Total Data Volume: {camera_df['Tot size'].sum():.2f} bytes\n\n")
                        
                        if 'UDP' in camera_df.columns:
                            udp_pct = camera_df['UDP'].mean() * 100
                            f.write(f"UDP Protocol Usage: {udp_pct:.1f}%\n\n")
                        
                        # Attacks on cameras
                        if 'predicted_attack' in camera_df.columns:
                            f.write("-" * 80 + "\n")
                            f.write("ATTACKS DETECTED ON CAMERA TRAFFIC\n")
                            f.write("-" * 80 + "\n\n")
                            
                            camera_attacks = camera_df['predicted_attack'].value_counts()
                            for attack, count in camera_attacks.items():
                                attack_pct = (count / camera_count) * 100
                                f.write(f"{attack:20s}: {count:8,d} flows ({attack_pct:6.2f}%)\n")
                            
                            f.write("\n")
                            
                            # Detailed attack analysis for cameras
                            f.write("-" * 80 + "\n")
                            f.write("DETAILED ATTACK ANALYSIS ON CAMERAS\n")
                            f.write("-" * 80 + "\n\n")
                            
                            for attack_type in camera_attacks.keys():
                                if attack_type == 'Benign':
                                    continue
                                
                                f.write(f"\n### {attack_type} on Camera Traffic ###\n")
                                attack_camera_df = camera_df[camera_df['predicted_attack'] == attack_type]
                                
                                if 'Rate' in attack_camera_df.columns:
                                    f.write(f"  Average Rate: {attack_camera_df['Rate'].mean():.2f}\n")
                                
                                if 'Duration' in attack_camera_df.columns:
                                    f.write(f"  Average Duration: {attack_camera_df['Duration'].mean():.2f}\n")
                                
                                if 'Tot size' in attack_camera_df.columns:
                                    f.write(f"  Average Packet Size: {attack_camera_df['Tot size'].mean():.2f}\n")
                        
                        f.write("\n" + "-" * 80 + "\n")
                        f.write("CAMERA SECURITY RECOMMENDATIONS\n")
                        f.write("-" * 80 + "\n\n")
                        
                        f.write("🎥 IMMEDIATE ACTIONS FOR CAMERA SECURITY:\n\n")
                        f.write("1. NETWORK ISOLATION:\n")
                        f.write("   - Place all cameras in separate VLAN\n")
                        f.write("   - Implement strict firewall rules\n")
                        f.write("   - Disable internet access for cameras if possible\n\n")
                        
                        f.write("2. ACCESS CONTROL:\n")
                        f.write("   - Change ALL default passwords immediately\n")
                        f.write("   - Use strong, unique passwords for each camera\n")
                        f.write("   - Enable two-factor authentication where available\n")
                        f.write("   - Implement MAC address filtering\n\n")
                        
                        f.write("3. FIRMWARE & UPDATES:\n")
                        f.write("   - Update camera firmware to latest version\n")
                        f.write("   - Enable automatic security updates\n")
                        f.write("   - Regularly check manufacturer security bulletins\n\n")
                        
                        f.write("4. FEATURE HARDENING:\n")
                        f.write("   - Disable UPnP on all cameras\n")
                        f.write("   - Disable unused features and ports\n")
                        f.write("   - Turn off cloud services if not needed\n")
                        f.write("   - Disable P2P connections\n\n")
                        
                        f.write("5. REMOTE ACCESS:\n")
                        f.write("   - Use VPN for all remote camera access\n")
                        f.write("   - Never expose cameras directly to internet\n")
                        f.write("   - Implement IP whitelisting\n\n")
                        
                        f.write("6. MONITORING:\n")
                        f.write("   - Enable camera access logging\n")
                        f.write("   - Monitor for unusual traffic patterns\n")
                        f.write("   - Set up alerts for unauthorized access attempts\n")
                        f.write("   - Regular security audits\n\n")
                        
                        # Mirai-specific recommendations
                        if 'Mirai' in camera_attacks.index:
                            mirai_count = camera_attacks['Mirai']
                            f.write("⚠️  CRITICAL: MIRAI BOTNET ACTIVITY DETECTED\n\n")
                            f.write(f"Mirai attacks on cameras: {mirai_count:,} flows\n\n")
                            f.write("URGENT MIRAI MITIGATION STEPS:\n")
                            f.write("   - Immediately isolate affected cameras\n")
                            f.write("   - Factory reset all potentially compromised cameras\n")
                            f.write("   - Scan entire network for botnet activity\n")
                            f.write("   - Block common Mirai C&C server ports (23, 2323, 48101)\n")
                            f.write("   - Monitor for scanning activity on ports 23, 2323\n")
                            f.write("   - Consider replacing cameras with more secure models\n\n")
                        
                        f.write("-" * 80 + "\n")
                        f.write("PRIORITY ACTION TIMELINE\n")
                        f.write("-" * 80 + "\n\n")
                        
                        f.write("IMMEDIATE (Next 24 hours):\n")
                        f.write("   ✓ Change all camera passwords\n")
                        f.write("   ✓ Isolate camera network\n")
                        f.write("   ✓ Disable UPnP and unused features\n")
                        f.write("   ✓ Review access logs for suspicious activity\n\n")
                        
                        f.write("SHORT-TERM (Next week):\n")
                        f.write("   ✓ Update all camera firmware\n")
                        f.write("   ✓ Implement VLAN separation\n")
                        f.write("   ✓ Configure VPN for remote access\n")
                        f.write("   ✓ Enable logging and monitoring\n\n")
                        
                        f.write("LONG-TERM (Next month):\n")
                        f.write("   ✓ Conduct full security audit\n")
                        f.write("   ✓ Implement IDS/IPS for camera network\n")
                        f.write("   ✓ Regular penetration testing\n")
                        f.write("   ✓ Security awareness training for staff\n")
                        f.write("   ✓ Review and update camera security policy\n\n")
                    
                    else:
                        f.write("No camera traffic detected in the analyzed data.\n\n")
                
                f.write("\n" + "=" * 80 + "\n")
                f.write("END OF REPORT\n")
                f.write("=" * 80 + "\n")
            
            self.results_text.insert(tk.END, 
                f"✓ Camera forensic report saved: {os.path.basename(report_path)}\n\n")
            messagebox.showinfo("Success", f"Camera forensic report saved to:\n{report_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Report generation failed:\n{str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkForensicApp(root)
    root.mainloop()    

    
