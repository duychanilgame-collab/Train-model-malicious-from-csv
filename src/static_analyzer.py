import os
import magic
import hashlib
import pefile
import yara
from pathlib import Path
import math
import numpy as np

class StaticAnalyzer:
    def __init__(self, config):
        self.config = config
        self.ghidra_path = config['tools']['ghidra']['path']
        self.yara_rules = self._load_yara_rules()

    def _load_yara_rules(self):
        rules_dir = Path(self.config['tools']['yara']['rules_path'])
        rule_files = {file.stem: str(file) for file in rules_dir.glob('*.yara')}
        if not rule_files:
            print("[!] No YARA rules found.")
            return None
        try:
            return yara.compile(filepaths=rule_files)
        except yara.Error as e:
            print(f"[!] Error compiling YARA rules: {e}")
            return None

    def analyze_file(self, file_path):
        results = {
            'file_metadata': self._extract_file_metadata(file_path),
            'hash_analysis': self._calculate_hashes(file_path),
            'entropy_analysis': self._analyze_entropy(file_path),
            'pe_analysis': self._analyze_pe_structure(file_path),
            'string_analysis': self._extract_strings(file_path),
            'yara_analysis': self._yara_scan(file_path),
            'risk_assessment': {}
        }
        results['risk_assessment'] = self._calculate_comprehensive_risk(results)
        return results

    def _extract_file_metadata(self, file_path):
        file_stat = os.stat(file_path)
        return {
            'filename': os.path.basename(file_path),
            'size_bytes': file_stat.st_size,
            'file_type': magic.from_file(file_path),
            'mime_type': magic.from_file(file_path, mime=True),
            'creation_time': file_stat.st_ctime,
            'modification_time': file_stat.st_mtime
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
            data = f.read(65536)  # Read first 64KB
        if not data:
            return {'overall_entropy': 0.0}
        entropy = 0.0
        for b in range(256):
            p_x = data.count(bytes([b])) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        return {'overall_entropy': round(entropy, 3)}

    def _analyze_pe_structure(self, file_path):
        try:
            pe = pefile.PE(file_path)
            return {
                'is_pe': True,
                'architecture': 'x86' if pe.FILE_HEADER.Machine == 0x14c else 'x64',
                'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            }
        except pefile.PEFormatError:
            return {'is_pe': False, 'error': 'Not a valid PE file'}

    def _extract_strings(self, file_path):
        strings = []
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b""):
                chunk_strings = [s.decode('utf-8', errors='ignore') for s in chunk.split() if len(s) > 4]
                strings.extend(chunk_strings)
        return {'total_strings': len(strings)}

    def _yara_scan(self, file_path):
        if not self.yara_rules:
            return {'matches': [], 'rules_loaded': 0}
        matches = self.yara_rules.match(file_path)
        return {
            'matches': [{'rule': m.rule} for m in matches],
            'match_count': len(matches)
        }

    def _calculate_comprehensive_risk(self, analysis_results):
        risk_score = 0
        if analysis_results['entropy_analysis']['overall_entropy'] > 7.5:
            risk_score += 25
        if analysis_results['pe_analysis'].get('is_pe', False):
            risk_score += 10
        if analysis_results['yara_analysis']['match_count'] > 0:
            risk_score += 30
        return {
            'overall_risk_score': min(risk_score, 100),
            'classification': 'MALWARE' if risk_score > 50 else 'BENIGN'
        }

if __name__ == "__main__":
    import json

    config_path = os.path.expanduser('~/malware_detection/config.json')
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found at {config_path}")

    with open(config_path) as f:
        config = json.load(f)

    analyzer = StaticAnalyzer(config)

    sample_path = os.path.expanduser('~/malware_detection/dataset/malware/sample1.exe')
    sample_path = os.path.expanduser('~/malware_detection/dataset/malware/sample2.exe')
    if not os.path.exists(sample_path):
        raise FileNotFoundError(f"Sample file not found at {sample_path}")

    results = analyzer.analyze_file(sample_path)
    print(json.dumps(results, indent=2))

