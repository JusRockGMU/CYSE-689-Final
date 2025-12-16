#!/usr/bin/env python3
"""
Nmap XML Parser - Extracts structured facts from Nmap scan files.

This module parses Nmap XML output and extracts key information:
- Target host information (IP, hostname, MAC)
- Open ports and their states
- Service detection (name, product, version)
- Operating system detection
- NSE script outputs

The extracted facts serve as ground truth for validating LLM-generated reports.
"""

import argparse
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
import sys


class NmapParser:
    """Parse Nmap XML files and extract structured facts."""
    
    def __init__(self, xml_file: Path):
        """Initialize parser with XML file path."""
        self.xml_file = xml_file
        self.tree = None
        self.root = None
        
    def parse(self) -> Dict[str, Any]:
        """Parse the Nmap XML file and extract all facts."""
        try:
            self.tree = ET.parse(self.xml_file)
            self.root = self.tree.getroot()
        except ET.ParseError as e:
            raise ValueError(f"Failed to parse XML file: {e}")
        
        # Extract all components
        scan_info = self._extract_scan_info()
        hosts = self._extract_hosts()
        
        facts = {
            'scan_info': scan_info,
            'hosts': hosts,
            'summary': self._generate_summary_from_hosts(hosts)
        }
        
        return facts
    
    def _extract_scan_info(self) -> Dict[str, Any]:
        """Extract scan metadata."""
        scan_info = {
            'scanner': self.root.get('scanner', 'unknown'),
            'version': self.root.get('version', 'unknown'),
            'command': self.root.get('args', ''),
            'start_time': self.root.get('start', ''),
            'start_str': self.root.get('startstr', ''),
        }
        
        # Get scan type information
        scaninfo = self.root.find('scaninfo')
        if scaninfo is not None:
            scan_info['type'] = scaninfo.get('type', '')
            scan_info['protocol'] = scaninfo.get('protocol', '')
            scan_info['services'] = scaninfo.get('services', '')
        
        return scan_info
    
    def _extract_hosts(self) -> List[Dict[str, Any]]:
        """Extract information about all hosts."""
        hosts = []
        
        for host in self.root.findall('host'):
            host_info = self._extract_host_info(host)
            if host_info:
                hosts.append(host_info)
        
        return hosts
    
    def _extract_host_info(self, host) -> Optional[Dict[str, Any]]:
        """Extract detailed information about a single host."""
        # Check host status
        status = host.find('status')
        if status is None or status.get('state') != 'up':
            return None
        
        host_info = {
            'status': status.get('state'),
            'reason': status.get('reason', ''),
            'addresses': self._extract_addresses(host),
            'hostnames': self._extract_hostnames(host),
            'ports': self._extract_ports(host),
            'os': self._extract_os(host),
        }
        
        return host_info
    
    def _extract_addresses(self, host) -> Dict[str, str]:
        """Extract IP and MAC addresses."""
        addresses = {}
        
        for addr in host.findall('address'):
            addr_type = addr.get('addrtype', '')
            addr_val = addr.get('addr', '')
            
            if addr_type == 'ipv4':
                addresses['ipv4'] = addr_val
            elif addr_type == 'ipv6':
                addresses['ipv6'] = addr_val
            elif addr_type == 'mac':
                addresses['mac'] = addr_val
                addresses['mac_vendor'] = addr.get('vendor', '')
        
        return addresses
    
    def _extract_hostnames(self, host) -> List[str]:
        """Extract hostnames."""
        hostnames = []
        
        hostnames_elem = host.find('hostnames')
        if hostnames_elem is not None:
            for hostname in hostnames_elem.findall('hostname'):
                name = hostname.get('name')
                if name:
                    hostnames.append(name)
        
        return hostnames
    
    def _extract_ports(self, host) -> List[Dict[str, Any]]:
        """Extract port and service information."""
        ports = []
        
        ports_elem = host.find('ports')
        if ports_elem is None:
            return ports
        
        for port in ports_elem.findall('port'):
            port_info = self._extract_port_info(port)
            if port_info:
                ports.append(port_info)
        
        return ports
    
    def _extract_port_info(self, port) -> Optional[Dict[str, Any]]:
        """Extract detailed information about a single port."""
        state = port.find('state')
        if state is None:
            return None
        
        port_info = {
            'port': int(port.get('portid', 0)),
            'protocol': port.get('protocol', 'tcp'),
            'state': state.get('state', 'unknown'),
            'reason': state.get('reason', ''),
            'service': self._extract_service(port),
            'scripts': self._extract_scripts(port),
        }
        
        return port_info
    
    def _extract_service(self, port) -> Dict[str, Any]:
        """Extract service detection information."""
        service_elem = port.find('service')
        if service_elem is None:
            return {}
        
        service = {
            'name': service_elem.get('name', ''),
            'product': service_elem.get('product', ''),
            'version': service_elem.get('version', ''),
            'extrainfo': service_elem.get('extrainfo', ''),
            'ostype': service_elem.get('ostype', ''),
            'method': service_elem.get('method', ''),
            'confidence': service_elem.get('conf', ''),
        }
        
        # Extract CPE (Common Platform Enumeration) for vulnerability matching
        cpes = []
        for cpe in service_elem.findall('cpe'):
            if cpe.text:
                cpes.append(cpe.text)
        if cpes:
            service['cpe'] = cpes
        
        return service
    
    def _extract_scripts(self, port) -> List[Dict[str, str]]:
        """Extract NSE script outputs."""
        scripts = []
        
        for script in port.findall('script'):
            script_info = {
                'id': script.get('id', ''),
                'output': script.get('output', ''),
            }
            scripts.append(script_info)
        
        return scripts
    
    def _extract_os(self, host) -> Dict[str, Any]:
        """Extract operating system detection information."""
        os_info = {}
        
        os_elem = host.find('os')
        if os_elem is None:
            return os_info
        
        # Get OS matches
        os_matches = []
        for osmatch in os_elem.findall('osmatch'):
            match = {
                'name': osmatch.get('name', ''),
                'accuracy': osmatch.get('accuracy', ''),
            }
            
            # Get OS classes
            osclasses = []
            for osclass in osmatch.findall('osclass'):
                osclass_info = {
                    'type': osclass.get('type', ''),
                    'vendor': osclass.get('vendor', ''),
                    'osfamily': osclass.get('osfamily', ''),
                    'osgen': osclass.get('osgen', ''),
                    'accuracy': osclass.get('accuracy', ''),
                }
                
                # Get CPEs
                cpes = []
                for cpe in osclass.findall('cpe'):
                    if cpe.text:
                        cpes.append(cpe.text)
                if cpes:
                    osclass_info['cpe'] = cpes
                
                osclasses.append(osclass_info)
            
            if osclasses:
                match['osclasses'] = osclasses
            
            os_matches.append(match)
        
        if os_matches:
            os_info['matches'] = os_matches
            # Store best match separately
            os_info['best_match'] = os_matches[0] if os_matches else None
        
        return os_info
    
    def _generate_summary_from_hosts(self, hosts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary statistics from parsed host data."""
        total_hosts = len(hosts)
        up_hosts = sum(1 for h in hosts if h.get('status') == 'up')
        
        # Count ports from parsed data
        total_ports = 0
        open_ports = 0
        services_found = set()
        
        for host in hosts:
            ports = host.get('ports', [])
            total_ports += len(ports)
            for port in ports:
                if port.get('state') == 'open':
                    open_ports += 1
                    service = port.get('service', {})
                    service_name = service.get('name')
                    if service_name:
                        services_found.add(service_name)
        
        summary = {
            'total_hosts': total_hosts,
            'up_hosts': up_hosts,
            'total_ports_scanned': total_ports,
            'open_ports': open_ports,
            'unique_services': len(services_found),
            'services_list': sorted(list(services_found)),
        }
        
        return summary


def parse_single_file(xml_file: Path, output_dir: Path) -> bool:
    """Parse a single Nmap XML file and save JSON output."""
    try:
        print(f"  Parsing: {xml_file.name}")
        
        parser = NmapParser(xml_file)
        facts = parser.parse()
        
        # Add metadata
        facts['metadata'] = {
            'source_file': xml_file.name,
            'parsed_at': datetime.now().isoformat(),
            'parser_version': '1.0.0',
        }
        
        # Save to JSON
        output_file = output_dir / f"{xml_file.stem}.json"
        with open(output_file, 'w') as f:
            json.dump(facts, f, indent=2)
        
        # Print summary
        summary = facts['summary']
        print(f"    → {summary['up_hosts']} host(s), "
              f"{summary['open_ports']} open port(s), "
              f"{summary['unique_services']} service(s)")
        
        return True
        
    except Exception as e:
        print(f"    [ERROR] {e}")
        return False


def main():
    """Main entry point for the parser."""
    parser = argparse.ArgumentParser(
        description='Parse Nmap XML files and extract structured facts.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Parse all XML files in a directory
  python parser.py --input data/raw_scans --output data/parsed_facts
  
  # Parse a single file
  python parser.py --input data/raw_scans/Bob-1.0.1.xml --output data/parsed_facts
  
  # Parse only first 3 files (for testing)
  python parser.py --input data/raw_scans --output data/parsed_facts --limit 3
        '''
    )
    
    parser.add_argument(
        '--input', '-i',
        type=Path,
        required=True,
        help='Input XML file or directory containing XML files'
    )
    
    parser.add_argument(
        '--output', '-o',
        type=Path,
        required=True,
        help='Output directory for JSON facts'
    )
    
    parser.add_argument(
        '--limit', '-l',
        type=int,
        default=None,
        help='Limit number of files to parse (for testing)'
    )
    
    args = parser.parse_args()
    
    # Validate input
    if not args.input.exists():
        print(f"Error: Input path does not exist: {args.input}")
        return 1
    
    # Create output directory
    args.output.mkdir(parents=True, exist_ok=True)
    
    # Get list of XML files to parse
    if args.input.is_file():
        xml_files = [args.input]
    else:
        xml_files = sorted(args.input.glob('*.xml'))
    
    if not xml_files:
        print(f"Error: No XML files found in {args.input}")
        return 1
    
    # Apply limit if specified
    if args.limit:
        xml_files = xml_files[:args.limit]
    
    # Parse all files
    print(f"\nParsing {len(xml_files)} Nmap XML file(s)...")
    print("=" * 60)
    
    success_count = 0
    for xml_file in xml_files:
        if parse_single_file(xml_file, args.output):
            success_count += 1
    
    print("=" * 60)
    print(f"\n[SUCCESS] Parsed {success_count}/{len(xml_files)} file(s)")
    print(f"[OUTPUT] Facts saved to: {args.output}/")
    
    return 0 if success_count == len(xml_files) else 1


if __name__ == '__main__':
    sys.exit(main())
