import os
import time
import psutil
import sys
from cryptography.hazmat.primitives import hashes, cmac, poly1305
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import hmac
import hashlib
from statistics import mean, stdev, median
import csv
import json
from Crypto.Hash import KMAC256
import siphash24


class ComprehensiveMACBenchmark:
    
    def __init__(self, iterations, message_sizes, cpu_frequency_mhz):
        self.iterations = iterations
        self.message_sizes = message_sizes
        self.cpu_frequency_mhz = cpu_frequency_mhz
        self.results = []
        
        # Schlüssel
        self.cmac_key = os.urandom(16)
        self.hmac_key = os.urandom(32)
        self.poly1305_key = os.urandom(32)
        self.gmac_key = os.urandom(32)
        self.kmac_key = os.urandom(32)
        self.siphash_key = os.urandom(16)
        
        # Algorithmen-Definitionen
        self.algorithms = [
            {
                'name': 'CMAC-AES-128',
                'key': 'cmac',
                'function': self.wrapper_cmac,
                'description': 'Cipher-based MAC (NIST SP 800-38B)',
                'key_size': 16,
                'tag_size': 16,
                'standard': 'NIST SP 800-38B'
            },
            {
                'name': 'HMAC-SHA256',
                'key': 'hmac',
                'function': self.wrapper_hmac,
                'description': 'Hash-based MAC (RFC 2104)',
                'key_size': 32,
                'tag_size': 32,
                'standard': 'RFC 2104'
            },
            {
                'name': 'Poly1305',
                'key': 'poly1305',
                'function': self.wrapper_poly1305,
                'description': 'Polynomial-based MAC (RFC 8439)',
                'key_size': 32,
                'tag_size': 16,
                'standard': 'RFC 8439'
            },
            {
                'name': 'GMAC',
                'key': 'gmac',
                'function': self.wrapper_gmac,
                'description': 'Galois MAC (NIST SP 800-38D)',
                'key_size': 32,
                'tag_size': 16,
                'standard': 'NIST SP 800-38D'
            },
            {
                'name': 'KMAC256',
                'key': 'kmac256',
                'function': self.wrapper_kmac256,
                'description': 'Keccak MAC (NIST SP 800-185)',
                'key_size': 32,
                'tag_size': 8,
                'standard': 'NIST SP 800-185'
            },
            {
                'name': 'SipHash-2-4',
                'key': 'siphash',
                'function': self.wrapper_siphash,
                'description': 'Fast short-input PRF (Aumasson & Bernstein)',
                'key_size': 16,
                'tag_size': 8,
                'standard': 'Research paper'
            }
        ]
    
    # Wrapper-Funktionen
    def wrapper_cmac(self, message):
        c = cmac.CMAC(algorithms.AES(self.cmac_key), backend=default_backend())
        c.update(message)
        return c.finalize()
    
    def wrapper_hmac(self, message):
        h = hmac.new(self.hmac_key, message, hashlib.sha256)
        return h.digest()
    
    def wrapper_poly1305(self, message):
        return poly1305.Poly1305.generate_tag(self.poly1305_key, message)
    
    def wrapper_gmac(self, message):
        aesgcm = AESGCM(self.gmac_key)
        nonce = os.urandom(12)
        return aesgcm.encrypt(nonce, b"", message)
    
    def wrapper_kmac256(self, message):
        mac = KMAC256.new(key=self.kmac_key, mac_len=8)
        mac.update(message)
        return mac.digest()
    
    def wrapper_siphash(self, message):
        hasher = siphash24.siphash24(self.siphash_key)
        hasher.update(message)
        return hasher.digest()
    
    def measure_with_statistics(self, mac_function, message, algorithm_name):
        timings = []
        process = psutil.Process()
        
        # Aufwärmphase
        for _ in range(10):
            result = mac_function(message)
            if result is None:
                return None
        
        # Messung
        mem_before = process.memory_info().rss / 1024
        
        for _ in range(self.iterations):
            start = time.perf_counter()
            tag = mac_function(message)
            if tag is None:
                return None
            end = time.perf_counter()
            timings.append((end - start) * 1_000_000)
        
        mem_after = process.memory_info().rss / 1024
        
        # Statistiken
        avg_time = mean(timings)
        std_time = stdev(timings) if len(timings) > 1 else 0
        med_time = median(timings)
        min_time = min(timings)
        max_time = max(timings)
        
        # Durchsatz (MB/s)
        throughput_mbps = (len(message) * 1_000_000) / (avg_time * 1024 * 1024)
        
        # CPU-Zyklen (geschätzt)
        estimated_cycles = (avg_time / 1_000_000) * self.cpu_frequency_mhz * 1_000_000
        cycles_per_byte = estimated_cycles / len(message) if len(message) > 0 else 0
        
        return {
            'algorithm': algorithm_name,
            'message_size': len(message),
            'avg_time_us': avg_time,
            'std_time_us': std_time,
            'median_time_us': med_time,
            'min_time_us': min_time,
            'max_time_us': max_time,
            'throughput_mbps': throughput_mbps,
            'estimated_cycles': estimated_cycles,
            'cycles_per_byte': cycles_per_byte,
            'memory_delta_kb': mem_after - mem_before,
            'tag_size': len(tag) if tag else 0,
            'iterations': self.iterations
        }
    
    def run_comprehensive_benchmark(self):
        "Führt Benchmark durch"
        print("=" * 80)
        print("UMFASSENDE MAC-VERFAHREN ANALYSE")
        print("=" * 80)
        print(f"CPU-Frequenz: {self.cpu_frequency_mhz} MHz (geschätzt)")
        print(f"Iterationen: {self.iterations}")
        print(f"Nachrichtengrößen: {self.message_sizes} Bytes")
        print("=" * 80)
        
        for size in self.message_sizes:
            message = os.urandom(size)
            
            print(f"\n{'='*80}")
            print(f"Nachrichtengröße: {size} Bytes")
            print(f"{'='*80}")
            
            size_results = []
            
            for idx, algo in enumerate(self.algorithms, 1):
                
                print(f"\n[{idx}/{len(self.algorithms)}] {algo['name']}...")
                
                results = self.measure_with_statistics(
                    algo['function'], message, algo['name']
                )
                
                if results is None:
                    print(f"Messung fehlgeschlagen")
                    continue
                
                print(f"  Durchschnitt:     {results['avg_time_us']:.3f} µs")
                print(f"  Standardabw.:     {results['std_time_us']:.3f} µs")
                print(f"  Median:           {results['median_time_us']:.3f} µs")
                print(f"  Min/Max:          {results['min_time_us']:.3f} / {results['max_time_us']:.3f} µs")
                print(f"  Durchsatz:        {results['throughput_mbps']:.2f} MB/s")
                print(f"  Cycles/Byte:      {results['cycles_per_byte']:.2f} cpb")
                print(f"  TAG-Größe:        {results['tag_size']} Bytes")
                
                size_results.append(results)
                self.results.append(results)
            
            # Vergleichstabelle für diese Größe
            if len(size_results) > 1:
                self.print_comparison_table(size_results)
    
    def print_comparison_table(self, results):
        """Erstellt Vergleichstabelle"""
        print(f"\n{'='*80}")
        print("VERGLEICHSTABELLE")
        print(f"{'='*80}")
        
        # Header
        print(f"{'Algorithmus':<20}", end='')
        for r in results:
            print(f"{r['algorithm']:<15}", end='')
        print()
        print("-" * 80)
        
        # Zeit
        print(f"{'Zeit (µs)':<20}", end='')
        for r in results:
            print(f"{r['avg_time_us']:<15.3f}", end='')
        print()
        
        # Durchsatz
        print(f"{'Durchsatz (MB/s)':<20}", end='')
        for r in results:
            print(f"{r['throughput_mbps']:<15.2f}", end='')
        print()
        
        # Cycles/Byte
        print(f"{'Cycles/Byte':<20}", end='')
        for r in results:
            print(f"{r['cycles_per_byte']:<15.2f}", end='')
        print()
        
        # TAG-Größe
        print(f"{'TAG-Größe (B)':<20}", end='')
        for r in results:
            print(f"{r['tag_size']:<15}", end='')
        print()
        
        # Ranking
        print(f"\n{'RANKING (schnellste zuerst):':<20}")
        sorted_results = sorted(results, key=lambda x: x['avg_time_us'])
        for rank, r in enumerate(sorted_results, 1):
            speedup = sorted_results[0]['avg_time_us'] / r['avg_time_us']
            print(f"  {rank}. {r['algorithm']:<25} {r['avg_time_us']:>8.3f} µs  ({speedup:.2f}x)")
    
    def export_detailed_csv(self, filename='mac_comprehensive_results.csv'):
        """Exportiert detaillierte Ergebnisse"""
        if not self.results:
            print("Keine Ergebnisse vorhanden!")
            return
        
        with open(filename, 'w', newline='') as f:
            fieldnames = self.results[0].keys()
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.results)
        
        print(f"\n Detaillierte Ergebnisse in '{filename}' gespeichert")

# Hauptprogramm
if __name__ == "__main__":
    print("\n" + "╔" + "═" * 78 + "╗")
    print("║" + " " * 10 + "MAC-VERFAHREN ANALYSE" + " " * 20 + "║")
    print("╚" + "═" * 78 + "╝\n")

    # Konfiguration
    ITERATIONS = 10000
    MESSAGE_SIZES = [2, 4, 8, 16]
    CPU_FREQUENCY = 3800
    
    # Benchmark ausführen
    benchmark = ComprehensiveMACBenchmark(
        iterations=ITERATIONS,
        message_sizes=MESSAGE_SIZES,
        cpu_frequency_mhz=CPU_FREQUENCY
    )
    
    benchmark.run_comprehensive_benchmark()
    
    # Exports
    benchmark.export_detailed_csv('mac_comprehensive_results.csv')
