import os
import magic
import hashlib
import pefile
import yara
from pathlib import Path
import math

class StaticAnalyzer:
    def __init__(self, config):
        self.config = config
        # Keep Ghidra path for future extension, currently using pefile for speed
        self.ghidra_path = config['tools']['ghidra']['path']
        self.yara_rules = self._load_yara_rules()

    def _load_yara_rules(self):
        rules_dir = Path(self.config['tools']['yara']['rules_path'])
        rule_files = {file.stem: str(file) for file in rules_dir.glob('*.yara')}
        if not rule_files:
            return None
        try:
            return yara.compile(filepaths=rule_files)
        except yara.Error as e:
            print(f"[!] YARA compilation error: {e}")
            return None

    def analyze_file(self, file_path):
        # Comprehensive feature extraction
        pe_info = self._analyze_pe_structure(file_path)
        
        results = {
            'file_metadata': self._extract_file_metadata(file_path),
            'hash_analysis': self._calculate_hashes(file_path),
            'entropy_analysis': self._analyze_entropy(file_path),
            'pe_analysis': pe_info,
            'string_analysis': self._extract_strings(file_path),
            'yara_analysis': self._yara_scan(file_path),
            # Data for Vectorization (TF-IDF)
            'api_call_text': " ".join(pe_info.get('api_sequence', [])) 
        }
        return results

    def _extract_file_metadata(self, file_path):
        file_stat = os.stat(file_path)
        return {
            'filename': os.path.basename(file_path),
            'size_bytes': file_stat.st_size,
            'mime_type': magic.from_file(file_path, mime=True)
        }

    def _calculate_hashes(self, file_path):
        hash_algorithms = {'md5': hashlib.md5(), 'sha256': hashlib.sha256()}
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b""):
                for hasher in hash_algorithms.values():
                    hasher.update(chunk)
        return {name: hasher.hexdigest() for name, hasher in hash_algorithms.items()}

    def _analyze_entropy(self, file_path):
        with open(file_path, 'rb') as f:
            data = f.read(65536)
        if not data: return {'overall_entropy': 0.0}
        entropy = 0.0
        for b in range(256):
            p_x = data.count(bytes([b])) / len(data)
            if p_x > 0: entropy += -p_x * math.log2(p_x)
        return {'overall_entropy': round(entropy, 3)}

    def _analyze_pe_structure(self, file_path):
        try:
            pe = pefile.PE(file_path)
            api_sequence = []
            suspicious_apis = ['VirtualAlloc', 'CreateRemoteThread', 'WriteProcessMemory', 'ShellExecute']
            suspicious_count = 0

            # Extract Imports (API Calls) - Meets API call traces requirement
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8', 'ignore')
                            api_sequence.append(func_name)
                            if any(s in func_name for s in suspicious_apis):
                                suspicious_count += 1
            
            return {
                'is_pe': True,
                'import_count': len(api_sequence),
                'suspicious_import_count': suspicious_count,
                'api_sequence': api_sequence  # Critical for Feature Vectorization
            }
        except Exception:
            return {'is_pe': False, 'import_count': 0, 'suspicious_import_count': 0, 'api_sequence': []}

    def _extract_strings(self, file_path):
        strings = []
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b""):
                chunk_strings = [s.decode('utf-8', errors='ignore') for s in chunk.split() if len(s) > 4]
                strings.extend(chunk_strings)
        return {'total_strings': len(strings)}

    def _yara_scan(self, file_path):
        if not self.yara_rules: return {'matches': [], 'match_count': 0}
        matches = self.yara_rules.match(file_path)
        return {'match_count': len(matches)}