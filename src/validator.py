#!/usr/bin/env python3
"""
Evidence Validator - Validates LLM-generated claims against parsed scan facts.

This module provides the core innovation of the project: systematic fact-checking
of LLM-generated penetration testing reports. It extracts claims from reports and
validates them against ground-truth data from Nmap scans.

Key functionality:
- Extract service and port claims from LLM reports
- Match claims against parsed Nmap facts
- Identify unsupported or hallucinated claims
- Generate evidence citations
- Compute validation metrics
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
from fuzzywuzzy import fuzz
from dataclasses import dataclass


@dataclass
class Claim:
    """Represents a claim extracted from LLM report."""
    claim_type: str  # 'port', 'service', 'version', 'cve', 'os'
    value: str
    context: str  # Surrounding text for reference
    line_number: int
    supported: bool = False
    evidence: Optional[str] = None
    confidence: float = 0.0


@dataclass
class ValidationResult:
    """Results of validating a report against facts."""
    total_claims: int
    supported_claims: int
    unsupported_claims: int
    claims_by_type: Dict[str, int]
    unsupported_by_type: Dict[str, int]
    claim_details: List[Claim]
    evidence_citation_rate: float
    hallucination_rate: float


class EvidenceValidator:
    """Validates LLM report claims against parsed scan facts."""
    
    def __init__(self, facts: Dict[str, Any]):
        """Initialize validator with parsed facts."""
        self.facts = facts
        self.host_info = facts['hosts'][0] if facts['hosts'] else {}
        self.ports = self.host_info.get('ports', [])
        self.summary = facts['summary']
        
        # Build lookup structures for fast validation
        self._build_lookups()
    
    def _build_lookups(self):
        """Build fast lookup structures from facts."""
        # Port numbers
        self.valid_ports = {port['port'] for port in self.ports}
        
        # Services
        self.valid_services = {}
        for port in self.ports:
            service = port.get('service', {})
            port_num = port['port']
            service_name = service.get('name', '').lower()
            if service_name:
                self.valid_services[service_name] = {
                    'port': port_num,
                    'product': service.get('product', ''),
                    'version': service.get('version', ''),
                    'cpe': service.get('cpe', [])
                }
        
        # Versions (product + version combinations)
        self.valid_versions = {}
        for port in self.ports:
            service = port.get('service', {})
            product = service.get('product', '').lower()
            version = service.get('version', '')
            if product and version:
                key = f"{product} {version}".lower()
                self.valid_versions[key] = {
                    'port': port['port'],
                    'product': product,
                    'version': version
                }
        
        # OS information
        os_info = self.host_info.get('os', {})
        best_match = os_info.get('best_match', {})
        self.valid_os = best_match.get('name', '').lower() if best_match else ''
    
    def validate_report(self, report_text: str) -> ValidationResult:
        """Validate entire report against facts."""
        claims = self._extract_claims(report_text)
        
        # Validate each claim
        for claim in claims:
            self._validate_claim(claim)
        
        # Compute metrics
        return self._compute_metrics(claims)
    
    def _extract_claims(self, text: str) -> List[Claim]:
        """Extract all claims from report text."""
        # Remove the validation section if it exists (to avoid extracting claims from flagged claims)
        if "## Evidence Validation Summary" in text:
            text = text.split("## Evidence Validation Summary")[0]
        
        claims = []
        claims.extend(self._extract_port_claims(text))
        claims.extend(self._extract_service_claims(text))
        claims.extend(self._extract_version_claims(text))
        claims.extend(self._extract_os_claims(text))
        return claims
    
    def _extract_port_claims(self, text: str) -> List[Claim]:
        """Extract port number claims from report."""
        claims = []
        lines = text.split('\n')
        
        # Pattern: "port 80", "Port 25468", etc.
        port_pattern = re.compile(r'\bport\s+(\d+)\b', re.IGNORECASE)
        
        for line_num, line in enumerate(lines, 1):
            for match in port_pattern.finditer(line):
                port_num = int(match.group(1))
                claims.append(Claim(
                    claim_type='port',
                    value=str(port_num),
                    context=line.strip(),
                    line_number=line_num
                ))
        
        return claims
    
    def _extract_service_claims(self, text: str) -> List[Claim]:
        """Extract service name claims from report."""
        claims = []
        lines = text.split('\n')
        
        # Common service patterns
        service_keywords = [
            'http', 'https', 'ssh', 'ftp', 'smtp', 'mysql', 'postgresql',
            'telnet', 'dns', 'ldap', 'smb', 'nfs', 'vnc', 'rdp'
        ]
        
        # Keywords that indicate recommendation/hardening context (not actual claims)
        exclude_keywords = ['disable', 'hardening', 'recommend', 'configure', 'unnecessary', 
                           'should', 'consider', 'implement', 'ensure', 'harden', 'allow',
                           'alternative', 'instead', 'replace', 'avoid']
        
        for line_num, line in enumerate(lines, 1):
            line_lower = line.lower()
            
            # Skip lines with recommendation/hardening keywords
            if any(keyword in line_lower for keyword in exclude_keywords):
                continue
            
            for service in service_keywords:
                # Look for service mentions in context (not just any occurrence)
                # Skip if service only appears in parentheses (e.g., "authentication (Telnet)")
                if re.search(rf'\({service}\)', line_lower, re.IGNORECASE):
                    continue
                    
                if re.search(rf'\b{service}\b.*\bservice\b', line_lower) or \
                   re.search(rf'\bservice.*\b{service}\b', line_lower):
                    claims.append(Claim(
                        claim_type='service',
                        value=service,
                        context=line.strip(),
                        line_number=line_num
                    ))
        
        return claims
    
    def _extract_version_claims(self, text: str) -> List[Claim]:
        """Extract software version claims from report."""
        claims = []
        lines = text.split('\n')
        
        # Improved pattern: more flexible, handles various formats
        # Matches: "Apache httpd 2.4.25", "OpenSSH 7.4p1", "MySQL 5.7"
        version_pattern = re.compile(
            r'\b([A-Z][a-zA-Z]+(?:\s+[a-zA-Z]+)?)\s+(?:version\s+)?(\d+\.\d+[^\s,\)\]]*)',
            re.IGNORECASE
        )
        
        # Keywords that indicate this is a version context
        version_context_keywords = ['version', 'running', 'detected', 'service', 'using', 'installed']
        # Keywords that indicate this is NOT a version claim (recommendations, CVE ranges, etc.)
        exclude_keywords = ['upgrade', 'update', 'through', 'protocol', 'recommend', 'prior', 'before', 'after', 'older', 'newer', 'cve', 'vulnerability', 'exploit']
        
        for line_num, line in enumerate(lines, 1):
            line_lower = line.lower()
            
            # Skip lines with exclude keywords
            if any(keyword in line_lower for keyword in exclude_keywords):
                continue
            
            # Only process lines with version context OR in technical sections
            has_context = any(keyword in line_lower for keyword in version_context_keywords)
            in_technical_section = any(marker in line for marker in ['**', '###', '##', '*'])
            
            if not (has_context or in_technical_section):
                continue
            
            for match in version_pattern.finditer(line):
                product = match.group(1).strip()
                version = match.group(2).strip()
                
                # Skip obvious false positives
                if version.lower().startswith('protocol'):
                    continue
                    
                # Skip common non-product words that get matched
                non_product_words = ['protocol', 'port', 'line', 'specifically', 'approximately', 
                                    'around', 'about', 'roughly', 'version', 'release', 'dated',
                                    'including', 'excluding', 'such', 'like', 'between', 'within',
                                    'as', 'the', 'for', 'while', 'this', 'that', 'with', 'from',
                                    'to', 'in', 'on', 'at', 'by', 'of', 'an', 'a', 'is', 'are',
                                    'was', 'were', 'be', 'been', 'being', 'have', 'has', 'had',
                                    'do', 'does', 'did', 'will', 'would', 'could', 'should',
                                    'vulnerabilities', 'vulnerability', 'issues', 'reported',
                                    'running', 'cli', 'server']
                
                # Check if the FULL product string or FIRST word is a non-product word
                first_word = product.split()[0].lower()
                if product.lower() in non_product_words or first_word in non_product_words:
                    continue
                    
                claims.append(Claim(
                    claim_type='version',
                    value=f"{product} {version}",
                    context=line.strip(),
                    line_number=line_num
                ))
        
        return claims
    
    def _extract_os_claims(self, text: str) -> List[Claim]:
        """Extract operating system claims from report."""
        claims = []
        lines = text.split('\n')
        
        # OS patterns
        os_keywords = ['linux', 'windows', 'unix', 'debian', 'ubuntu', 'centos', 'redhat']
        
        for line_num, line in enumerate(lines, 1):
            line_lower = line.lower()
            for os_name in os_keywords:
                if re.search(rf'\b{os_name}\b', line_lower):
                    # Check if it's in OS context
                    if 'operating system' in line_lower or 'os:' in line_lower or 'platform' in line_lower:
                        claims.append(Claim(
                            claim_type='os',
                            value=os_name,
                            context=line.strip(),
                            line_number=line_num
                        ))
        
        return claims
    
    def _validate_claim(self, claim: Claim):
        """Validate a single claim against facts."""
        if claim.claim_type == 'port':
            self._validate_port_claim(claim)
        elif claim.claim_type == 'service':
            self._validate_service_claim(claim)
        elif claim.claim_type == 'version':
            self._validate_version_claim(claim)
        elif claim.claim_type == 'os':
            self._validate_os_claim(claim)
    
    def _validate_port_claim(self, claim: Claim):
        """Validate port number claim."""
        port_num = int(claim.value)
        
        if port_num in self.valid_ports:
            claim.supported = True
            claim.confidence = 1.0
            
            # Find port details for evidence
            port_info = next((p for p in self.ports if p['port'] == port_num), None)
            if port_info:
                service = port_info.get('service', {})
                claim.evidence = f"Port {port_num}/{port_info['protocol']} - {service.get('name', 'unknown')} ({port_info['state']})"
        else:
            claim.supported = False
            claim.confidence = 0.0
            claim.evidence = f"Port {port_num} not found in scan results"
    
    def _validate_service_claim(self, claim: Claim):
        """Validate service name claim."""
        service_name = claim.value.lower()
        
        # Service name synonyms mapping
        service_synonyms = {
            'dns': 'domain',
            'smb': 'netbios-ssn',
            'web': 'http',
            'database': 'mysql',
            'db': 'mysql'
        }
        
        # Check if claimed service is a known synonym
        if service_name in service_synonyms:
            canonical_name = service_synonyms[service_name]
            if canonical_name in self.valid_services:
                claim.supported = True
                claim.confidence = 1.0
                service_info = self.valid_services[canonical_name]
                claim.evidence = f"Matched {service_name} to {canonical_name} on port {service_info['port']}"
                return
        
        if service_name in self.valid_services:
            claim.supported = True
            claim.confidence = 1.0
            
            service_info = self.valid_services[service_name]
            claim.evidence = f"{service_name} service on port {service_info['port']}"
            if service_info['product']:
                claim.evidence += f" ({service_info['product']})"
        else:
            # Try fuzzy matching for common variations
            best_match = None
            best_score = 0
            
            for valid_service in self.valid_services.keys():
                score = fuzz.ratio(service_name, valid_service)
                if score > best_score:
                    best_score = score
                    best_match = valid_service
            
            if best_score >= 75:  # Lowered from 80% to 75%
                claim.supported = True
                claim.confidence = best_score / 100.0
                service_info = self.valid_services[best_match]
                claim.evidence = f"Matched to {best_match} on port {service_info['port']} (confidence: {claim.confidence:.2f})"
            else:
                claim.supported = False
                claim.confidence = 0.0
                claim.evidence = f"Service '{service_name}' not found in scan results"
    
    def _normalize_version_string(self, version_str: str) -> str:
        """Normalize version string for matching."""
        # Remove common keywords
        normalized = re.sub(r'\bversion\s+', '', version_str, flags=re.IGNORECASE)
        
        # Normalize version suffixes: "2.0.8+" -> "2.0.8 or later"
        normalized = re.sub(r'(\d+\.\d+[^\s]*)\+', r'\1 or later', normalized)
        
        # Remove extra whitespace
        normalized = ' '.join(normalized.split())
        return normalized.lower().strip()
    
    def _validate_version_claim(self, claim: Claim):
        """Validate software version claim."""
        # Normalize the claim for better matching
        version_str = self._normalize_version_string(claim.value)
        
        # Direct match
        if version_str in self.valid_versions:
            claim.supported = True
            claim.confidence = 1.0
            
            version_info = self.valid_versions[version_str]
            claim.evidence = f"{version_info['product']} {version_info['version']} on port {version_info['port']}"
            return
        
        # Try matching just the product name and version number separately
        # This handles cases like "Apache httpd 2.4.25" vs "httpd 2.4.25"
        parts = version_str.split()
        if len(parts) >= 2:
            # Try different combinations
            for i in range(len(parts) - 1):
                test_str = ' '.join(parts[i:])
                if test_str in self.valid_versions:
                    claim.supported = True
                    claim.confidence = 0.95
                    version_info = self.valid_versions[test_str]
                    claim.evidence = f"Matched to {test_str} (partial product name match)"
                    return
        
        # Try prefix matching: "openssh 5.9p1" should match "openssh 5.9p1 debian 5ubuntu1.10"
        for valid_version in self.valid_versions.keys():
            if valid_version.startswith(version_str):
                claim.supported = True
                claim.confidence = 0.90
                version_info = self.valid_versions[valid_version]
                claim.evidence = f"Matched to {valid_version} (version prefix match)"
                return
        
        # Try fuzzy matching
        best_match = None
        best_score = 0
        
        for valid_version in self.valid_versions.keys():
            score = fuzz.ratio(version_str, valid_version)
            if score > best_score:
                best_score = score
                best_match = valid_version
        
        if best_score >= 80:  # Lowered threshold from 85 to 80
            claim.supported = True
            claim.confidence = best_score / 100.0
            version_info = self.valid_versions[best_match]
            claim.evidence = f"Matched to {best_match} (confidence: {claim.confidence:.2f})"
        else:
            claim.supported = False
            claim.confidence = 0.0
            claim.evidence = f"Version '{version_str}' not found in scan results"
    
    def _validate_os_claim(self, claim: Claim):
        """Validate operating system claim."""
        os_name = claim.value.lower()
        
        if os_name in self.valid_os.lower():
            claim.supported = True
            claim.confidence = 1.0
            claim.evidence = f"OS detected as: {self.valid_os}"
        else:
            # Fuzzy match for OS
            score = fuzz.partial_ratio(os_name, self.valid_os.lower())
            if score >= 70:
                claim.supported = True
                claim.confidence = score / 100.0
                claim.evidence = f"Partial match to {self.valid_os} (confidence: {claim.confidence:.2f})"
            else:
                claim.supported = False
                claim.confidence = 0.0
                claim.evidence = f"OS '{os_name}' does not match detected OS: {self.valid_os}"
    
    def _compute_metrics(self, claims: List[Claim]) -> ValidationResult:
        """Compute validation metrics from claims."""
        total = len(claims)
        supported = sum(1 for c in claims if c.supported)
        unsupported = total - supported
        
        # Count by type
        claims_by_type = {}
        unsupported_by_type = {}
        
        for claim in claims:
            claim_type = claim.claim_type
            claims_by_type[claim_type] = claims_by_type.get(claim_type, 0) + 1
            if not claim.supported:
                unsupported_by_type[claim_type] = unsupported_by_type.get(claim_type, 0) + 1
        
        # Calculate rates
        evidence_citation_rate = (supported / total * 100) if total > 0 else 0.0
        hallucination_rate = (unsupported / total * 100) if total > 0 else 0.0
        
        return ValidationResult(
            total_claims=total,
            supported_claims=supported,
            unsupported_claims=unsupported,
            claims_by_type=claims_by_type,
            unsupported_by_type=unsupported_by_type,
            claim_details=claims,
            evidence_citation_rate=evidence_citation_rate,
            hallucination_rate=hallucination_rate
        )
    
    def generate_validation_report(self, result: ValidationResult, output_file: Path):
        """Generate detailed validation report."""
        report = f"""# Evidence Validation Report

## Summary Statistics

- **Total Claims Extracted**: {result.total_claims}
- **Supported Claims**: {result.supported_claims} ({result.evidence_citation_rate:.1f}%)
- **Unsupported Claims**: {result.unsupported_claims} ({result.hallucination_rate:.1f}%)

## Claims by Type

| Claim Type | Total | Supported | Unsupported | Support Rate |
|------------|-------|-----------|-------------|--------------|
"""
        
        for claim_type, count in result.claims_by_type.items():
            unsupported_count = result.unsupported_by_type.get(claim_type, 0)
            supported_count = count - unsupported_count
            support_rate = (supported_count / count * 100) if count > 0 else 0
            report += f"| {claim_type.capitalize()} | {count} | {supported_count} | {unsupported_count} | {support_rate:.1f}% |\n"
        
        # List unsupported claims
        if result.unsupported_claims > 0:
            report += "\n## Unsupported Claims\n\n"
            report += "The following claims could not be verified against scan data:\n\n"
            
            for claim in result.claim_details:
                if not claim.supported:
                    report += f"### Line {claim.line_number}: {claim.claim_type.capitalize()} Claim\n"
                    report += f"- **Claim**: {claim.value}\n"
                    report += f"- **Context**: {claim.context[:100]}...\n"
                    report += f"- **Reason**: {claim.evidence}\n\n"
        
        # List supported claims with evidence
        report += "\n## Supported Claims with Evidence\n\n"
        
        for claim in result.claim_details:
            if claim.supported:
                report += f"### {claim.claim_type.capitalize()}: {claim.value}\n"
                report += f"- **Evidence**: {claim.evidence}\n"
                report += f"- **Confidence**: {claim.confidence:.2f}\n\n"
        
        # Write report
        with open(output_file, 'w') as f:
            f.write(report)


def validate_report_file(report_file: Path, facts_file: Path, output_dir: Path) -> ValidationResult:
    """Validate a single report file against facts."""
    # Load facts
    with open(facts_file, 'r') as f:
        facts = json.load(f)
    
    # Load report
    with open(report_file, 'r') as f:
        report_text = f.read()
    
    # Validate
    validator = EvidenceValidator(facts)
    result = validator.validate_report(report_text)
    
    # Generate validation report
    validation_report_file = output_dir / f"{report_file.stem}_validation.md"
    validator.generate_validation_report(result, validation_report_file)
    
    return result


if __name__ == '__main__':
    # Simple test
    import sys
    
    if len(sys.argv) != 4:
        print("Usage: python validator.py <report.md> <facts.json> <output_dir>")
        sys.exit(1)
    
    report_file = Path(sys.argv[1])
    facts_file = Path(sys.argv[2])
    output_dir = Path(sys.argv[3])
    output_dir.mkdir(parents=True, exist_ok=True)
    
    result = validate_report_file(report_file, facts_file, output_dir)
    
    print(f"\n[VALIDATION RESULTS]")
    print(f"Total Claims: {result.total_claims}")
    print(f"Supported: {result.supported_claims} ({result.evidence_citation_rate:.1f}%)")
    print(f"Unsupported: {result.unsupported_claims} ({result.hallucination_rate:.1f}%)")
    print(f"\nValidation report saved to: {output_dir}/")
