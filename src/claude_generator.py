#!/usr/bin/env python3
"""
Claude Report Generator - Generate pentest reports using Claude API.

This generator uses Anthropic's Claude API to create penetration testing reports
from parsed Nmap facts. It serves as an external comparison to the Ollama-based
baseline, demonstrating that our validation framework works across different LLMs.

Model: Claude Haiku 3.5 (cost-effective, fast)
"""

import argparse
import json
import os
from pathlib import Path
from typing import Dict, Any
from datetime import datetime
import sys

# Import Anthropic SDK
from anthropic import Anthropic

# Import our validator (Iteration 7)
from validator import EvidenceValidator, ValidationResult


class ClaudeReportGenerator:
    """Generate pentest reports using Claude API."""
    
    def __init__(self, model: str = "claude-3-5-haiku-20241022"):
        """Initialize generator with Claude model."""
        api_key = os.getenv('ANTHROPIC_API_KEY')
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable not set")
        
        self.client = Anthropic(api_key=api_key)
        self.model = model
        
        self.report_template = """# Penetration Testing Report
**[EVIDENCE-VALIDATED - Claude]**

## Target Information
- **Target IP**: {target_ip}
- **Scan Date**: {scan_date}
- **Report Generated**: {report_date}
- **Generator**: Claude API ({model})
- **Validation Status**: {validation_status}

## Executive Summary

{executive_summary}

## Technical Findings

{technical_findings}

## Service Analysis

{service_analysis}

## Security Recommendations

{recommendations}

## Detailed Port Information

{port_details}

{validation_summary}

---
*Report generated using Claude API with evidence-grounding validation*
*Model: {model}*
*Unsupported claim rate: {hallucination_rate:.1f}%*
"""
    
    def load_facts(self, facts_file: Path) -> Dict[str, Any]:
        """Load parsed facts from JSON file."""
        with open(facts_file, 'r') as f:
            return json.load(f)
    
    def _call_claude(self, prompt: str, max_tokens: int = 2000) -> str:
        """Call Claude API with prompt."""
        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            return message.content[0].text
        except Exception as e:
            print(f"    [ERROR] Claude API call failed: {e}")
            return f"Error generating content: {e}"
    
    def generate_report(self, facts: Dict[str, Any]) -> tuple:
        """Generate complete pentest report using Claude with validation."""
        # Extract key information
        host_info = facts['hosts'][0] if facts['hosts'] else {}
        target_ip = host_info.get('addresses', {}).get('ipv4', 'Unknown')
        scan_date = facts['scan_info'].get('start_str', 'Unknown')
        summary = facts['summary']
        
        # Generate sections using Claude
        print(f"  Generating executive summary...")
        executive_summary = self._generate_executive_summary(facts)
        
        print(f"  Generating technical findings...")
        technical_findings = self._generate_technical_findings(facts)
        
        print(f"  Generating service analysis...")
        service_analysis = self._generate_service_analysis(facts)
        
        print(f"  Generating recommendations...")
        recommendations = self._generate_recommendations(facts)
        
        print(f"  Formatting port details...")
        port_details = self._format_port_details(facts)
        
        # Assemble initial report
        initial_report = f"""# Penetration Testing Report
**[Claude-Generated]**

## Target Information
- **Target IP**: {target_ip}
- **Scan Date**: {scan_date}
- **Report Generated**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
- **Generator**: Claude API ({self.model})

## Executive Summary
{executive_summary}

## Technical Findings
{technical_findings}

## Service Analysis
{service_analysis}

## Security Recommendations
{recommendations}

## Detailed Port Information
{port_details}
"""
        
        # VALIDATE the report
        print(f"  Validating report against scan facts...")
        validator = EvidenceValidator(facts)
        validation = validator.validate_report(initial_report)
        
        # Generate flagged claims section
        flagged_section = self._generate_flagged_section(validation)
        
        # Determine validation status
        validation_status = self._get_validation_status(validation.hallucination_rate)
        
        # Assemble final report with validation info
        report = self.report_template.format(
            target_ip=target_ip,
            scan_date=scan_date,
            report_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            model=self.model,
            validation_status=validation_status,
            executive_summary=executive_summary,
            technical_findings=technical_findings,
            service_analysis=service_analysis,
            recommendations=recommendations,
            port_details=port_details,
            validation_summary=flagged_section,
            hallucination_rate=validation.hallucination_rate
        )
        
        return report, validation
    
    def _generate_executive_summary(self, facts: Dict[str, Any]) -> str:
        """Generate executive summary using Claude."""
        summary = facts['summary']
        services = ', '.join(summary['services_list'][:10])
        
        prompt = f"""You are a penetration tester writing an executive summary for a security assessment.

Target Information:
- {summary['open_ports']} open ports discovered
- {summary['unique_services']} unique services identified
- Services found: {services}

Write a concise executive summary (3-4 paragraphs) that:
1. Summarizes the scope of the assessment
2. Highlights the key findings
3. Provides overall risk assessment
4. States primary security concerns

IMPORTANT: Only mention services and ports that are explicitly provided above. Do not infer or assume additional services.

Be direct and professional. Do not use markdown formatting in your response."""

        return self._call_claude(prompt)
    
    def _generate_technical_findings(self, facts: Dict[str, Any]) -> str:
        """Generate detailed technical findings using Claude."""
        host = facts['hosts'][0] if facts['hosts'] else {}
        ports = host.get('ports', [])
        
        # Create concise port summary
        port_summary = []
        for port in ports[:15]:
            service = port.get('service', {})
            port_summary.append({
                'port': port['port'],
                'service': service.get('name', 'unknown'),
                'product': service.get('product', ''),
                'version': service.get('version', '')
            })
        
        prompt = f"""You are a penetration tester documenting technical findings.

Discovered Services (FROM SCAN):
{json.dumps(port_summary, indent=2)}

Write detailed technical findings that:
1. List each significant service discovery
2. Identify version information and potential vulnerabilities
3. Assess potential attack vectors
4. Rank findings by severity (Critical, High, Medium, Low)

CRITICAL CONSTRAINTS:
- Only reference ports, services, and versions EXACTLY as shown above
- Do not mention services not in the scan results
- When citing versions, use the exact version strings provided
- Clearly distinguish between confirmed findings and theoretical concerns

Format as numbered list with severity labels. Be specific about security implications."""

        return self._call_claude(prompt, max_tokens=3000)
    
    def _generate_service_analysis(self, facts: Dict[str, Any]) -> str:
        """Generate service-specific analysis using Claude."""
        host = facts['hosts'][0] if facts['hosts'] else {}
        ports = host.get('ports', [])
        os_info = host.get('os', {}).get('best_match', {})
        
        services_detail = []
        for port in ports[:10]:
            service = port.get('service', {})
            if service.get('name'):
                services_detail.append({
                    'name': service.get('name'),
                    'product': service.get('product', ''),
                    'version': service.get('version', ''),
                    'port': port['port']
                })
        
        os_name = os_info.get('name', 'Unknown')
        
        prompt = f"""You are analyzing services discovered during a penetration test.

Operating System: {os_name}

Services Detected:
{json.dumps(services_detail, indent=2)}

For each major service category, provide:
1. Service purpose and functionality
2. Common vulnerabilities for this version
3. Security configuration concerns
4. Recommended testing approaches

IMPORTANT: Only analyze services explicitly listed above. Reference versions exactly as shown.

Be technical and specific. Focus on actionable security insights."""

        return self._call_claude(prompt, max_tokens=2500)
    
    def _generate_recommendations(self, facts: Dict[str, Any]) -> str:
        """Generate security recommendations using Claude."""
        summary = facts['summary']
        host = facts['hosts'][0] if facts['hosts'] else {}
        ports = host.get('ports', [])
        
        services = [p.get('service', {}).get('name', '') for p in ports if p.get('service', {}).get('name')]
        
        prompt = f"""You are providing security recommendations for a penetration test.

Assessment Results:
- {summary['open_ports']} open ports
- {summary['unique_services']} services exposed
- Key services: {', '.join(services[:8])}

Provide prioritized security recommendations:
1. Immediate actions (Critical priority)
2. Short-term improvements (High priority)
3. Long-term security enhancements (Medium priority)
4. General hardening measures

Format as numbered lists under each category. Be specific and actionable."""

        return self._call_claude(prompt, max_tokens=2000)
    
    def _format_port_details(self, facts: Dict[str, Any]) -> str:
        """Format detailed port information."""
        host = facts['hosts'][0] if facts['hosts'] else {}
        ports = host.get('ports', [])
        
        if not ports:
            return "No open ports detected."
        
        details = []
        for port in ports:
            service = port.get('service', {})
            
            port_info = f"""### Port {port['port']}/{port['protocol']}
**State**: {port['state']}  
**Service**: {service.get('name', 'unknown')}  
**Product**: {service.get('product', 'N/A')}  
**Version**: {service.get('version', 'N/A')}  
**Extra Info**: {service.get('extrainfo', 'N/A')}
"""
            
            scripts = port.get('scripts', [])
            if scripts:
                port_info += "\n**NSE Script Results**:\n"
                for script in scripts[:3]:
                    script_output = script['output'].replace('\n', ' ')[:100]
                    port_info += f"- {script['id']}: {script_output}...\n"
            
            details.append(port_info)
        
        return '\n'.join(details)
    
    def _generate_flagged_section(self, validation: ValidationResult) -> str:
        """Generate section describing flagged claims."""
        if validation.unsupported_claims == 0:
            return "\n## Evidence Validation Summary\n\nAll claims in this report were validated against scan data.\n"
        
        section = f"\n## Evidence Validation Summary\n\n"
        section += f"- **Total Claims**: {validation.total_claims}\n"
        section += f"- **Supported Claims**: {validation.supported_claims} ({validation.evidence_citation_rate:.1f}%)\n"
        section += f"- **Flagged Claims**: {validation.unsupported_claims} ({validation.hallucination_rate:.1f}%)\n\n"
        section += f"\n### Flagged Claims ({validation.unsupported_claims} total)\n\n"
        section += "The following claims could not be verified against scan data:\n\n"
        
        for claim in validation.claim_details:
            if not claim.supported:
                section += f"- **{claim.claim_type.capitalize()}**: {claim.value}\n"
                section += f"  - Context: {claim.context[:80]}...\n"
                section += f"  - Issue: {claim.evidence}\n\n"
        
        section += "*Note: Flagged claims may represent theoretical concerns or require additional verification.*\n"
        
        return section
    
    def _get_validation_status(self, hallucination_rate: float) -> str:
        """Determine validation status based on hallucination rate."""
        if hallucination_rate < 5:
            return "HIGH CONFIDENCE - Minimal unverified claims"
        elif hallucination_rate < 15:
            return "MODERATE CONFIDENCE - Some unverified claims present"
        elif hallucination_rate < 30:
            return "LOW CONFIDENCE - Multiple unverified claims"
        else:
            return "CAUTION - Significant unverified content"


def generate_single_report(facts_file: Path, output_dir: Path, model: str) -> bool:
    """Generate validated Claude report for a single facts file."""
    try:
        print(f"  Processing: {facts_file.name}")
        
        generator = ClaudeReportGenerator(model=model)
        facts = generator.load_facts(facts_file)
        
        report, validation = generator.generate_report(facts)
        
        # Save report
        output_file = output_dir / f"{facts_file.stem}_claude.md"
        with open(output_file, 'w') as f:
            f.write(report)
        
        # Save validation metrics
        metrics_file = output_dir / f"{facts_file.stem}_metrics.json"
        metrics = {
            'total_claims': validation.total_claims,
            'supported_claims': validation.supported_claims,
            'unsupported_claims': validation.unsupported_claims,
            'evidence_citation_rate': validation.evidence_citation_rate,
            'hallucination_rate': validation.hallucination_rate,
            'claims_by_type': validation.claims_by_type,
            'unsupported_by_type': validation.unsupported_by_type
        }
        with open(metrics_file, 'w') as f:
            json.dump(metrics, f, indent=2)
        
        print(f"    [SUCCESS] Report saved - {validation.hallucination_rate:.1f}% unsupported claims")
        return True
        
    except Exception as e:
        print(f"    [ERROR] {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Main entry point for Claude report generator."""
    parser = argparse.ArgumentParser(
        description='Generate penetration testing reports using Claude API.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Generate Claude reports for all parsed facts
  export ANTHROPIC_API_KEY="your-key"
  python claude_generator.py --facts data/parsed_facts --output data/reports/claude
  
  # Generate report for single file
  python claude_generator.py --facts data/parsed_facts/Bob-1.0.1.json --output data/reports/claude
  
  # Limit to first 3 files (testing)
  python claude_generator.py --facts data/parsed_facts --output data/reports/claude --limit 3
        '''
    )
    
    parser.add_argument(
        '--facts', '-f',
        type=Path,
        required=True,
        help='Input JSON facts file or directory'
    )
    
    parser.add_argument(
        '--output', '-o',
        type=Path,
        required=True,
        help='Output directory for reports'
    )
    
    parser.add_argument(
        '--model', '-m',
        type=str,
        default='claude-3-5-haiku-20241022',
        help='Claude model to use (default: claude-3-5-haiku-20241022)'
    )
    
    parser.add_argument(
        '--limit', '-l',
        type=int,
        default=None,
        help='Limit number of reports to generate (for testing)'
    )
    
    args = parser.parse_args()
    
    # Check for API key
    if not os.getenv('ANTHROPIC_API_KEY'):
        print("[ERROR] ANTHROPIC_API_KEY environment variable not set")
        print("Set it with: export ANTHROPIC_API_KEY='your-key'")
        return 1
    
    # Validate input
    if not args.facts.exists():
        print(f"[ERROR] Input path does not exist: {args.facts}")
        return 1
    
    # Create output directory
    args.output.mkdir(parents=True, exist_ok=True)
    
    # Get list of fact files
    if args.facts.is_file():
        fact_files = [args.facts]
    else:
        fact_files = sorted(args.facts.glob('*.json'))
    
    if not fact_files:
        print(f"[ERROR] No JSON files found in {args.facts}")
        return 1
    
    # Apply limit if specified
    if args.limit:
        fact_files = fact_files[:args.limit]
    
    # Generate reports
    print(f"\nGenerating {len(fact_files)} Claude report(s) using {args.model}...")
    print("=" * 60)
    
    success_count = 0
    for fact_file in fact_files:
        if generate_single_report(fact_file, args.output, args.model):
            success_count += 1
    
    print("=" * 60)
    print(f"\n[SUCCESS] Generated {success_count}/{len(fact_files)} report(s)")
    print(f"[OUTPUT] Reports saved to: {args.output}/")
    
    return 0 if success_count == len(fact_files) else 1


if __name__ == '__main__':
    sys.exit(main())
