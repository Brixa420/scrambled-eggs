"""
Compliance Module for HSM

This module provides compliance and certification functionality for the HSM,
including FIPS 140-3 validation, Common Criteria, and security audit support.
"""
from typing import Dict, List, Optional, Any, Set
from enum import Enum, auto
from datetime import datetime, timedelta
import logging
import json
import hashlib
import hmac
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
import platform
import subprocess
import tempfile

class ComplianceLevel(Enum):
    """Compliance levels for different standards."""
    NOT_APPLICABLE = 0
    SELF_ASSESSED = 1
    IN_PROGRESS = 2
    CERTIFIED = 3
    VALIDATED = 4

class ComplianceStatus(Enum):
    """Compliance status."""
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    PASSED = "passed"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"

@dataclass
class ComplianceRequirement:
    """A single compliance requirement."""
    id: str
    name: str
    description: str
    category: str
    level: ComplianceLevel
    status: ComplianceStatus = ComplianceStatus.NOT_STARTED
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    last_verified: Optional[datetime] = None
    next_verification: Optional[datetime] = None
    requirements: List[str] = field(default_factory=list)  # References to other requirements
    controls: List[Dict[str, Any]] = field(default_factory=list)  # Security controls
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary."""
        result = asdict(self)
        result['level'] = self.level.name
        result['status'] = self.status.value
        if self.last_verified:
            result['last_verified'] = self.last_verified.isoformat()
        if self.next_verification:
            result['next_verification'] = self.next_verification.isoformat()
        return result

class ComplianceModule:
    """Base class for compliance modules."""
    
    def __init__(self):
        self.name = self.__class__.__name__
        self.requirements: Dict[str, ComplianceRequirement] = {}
        self.logger = logging.getLogger(f"scrambled_eggs.compliance.{self.name.lower()}")
        self.initialize_requirements()
    
    def initialize_requirements(self) -> None:
        """Initialize the compliance requirements for this module."""
        raise NotImplementedError
    
    def get_requirements(self) -> Dict[str, ComplianceRequirement]:
        """Get all requirements for this module."""
        return self.requirements
    
    def get_requirement(self, req_id: str) -> Optional[ComplianceRequirement]:
        """Get a specific requirement by ID."""
        return self.requirements.get(req_id)
    
    def verify_requirement(self, req_id: str) -> bool:
        """Verify a specific requirement."""
        req = self.get_requirement(req_id)
        if not req:
            self.logger.error(f"Requirement not found: {req_id}")
            return False
        
        try:
            # Default implementation checks if all dependent requirements are met
            for dep_id in req.requirements:
                dep_req = self.get_requirement(dep_id)
                if not dep_req or dep_req.status != ComplianceStatus.PASSED:
                    req.status = ComplianceStatus.FAILED
                    req.evidence.append({
                        'timestamp': datetime.utcnow().isoformat(),
                        'status': 'failed',
                        'message': f'Dependency requirement not met: {dep_id}'
                    })
                    return False
            
            # If we get here, all dependencies are met
            req.status = ComplianceStatus.PASSED
            req.last_verified = datetime.utcnow()
            req.next_verification = req.last_verified + timedelta(days=30)  # Default to monthly verification
            req.evidence.append({
                'timestamp': req.last_verified.isoformat(),
                'status': 'passed',
                'message': 'Requirement verified successfully'
            })
            return True
            
        except Exception as e:
            self.logger.error(f"Error verifying requirement {req_id}: {str(e)}")
            req.status = ComplianceStatus.FAILED
            req.evidence.append({
                'timestamp': datetime.utcnow().isoformat(),
                'status': 'error',
                'message': f'Error verifying requirement: {str(e)}'
            })
            return False
    
    def get_status(self) -> Dict[str, Any]:
        """Get the compliance status for this module."""
        total = len(self.requirements)
        passed = sum(1 for r in self.requirements.values() if r.status == ComplianceStatus.PASSED)
        failed = sum(1 for r in self.requirements.values() if r.status == ComplianceStatus.FAILED)
        in_progress = sum(1 for r in self.requirements.values() if r.status == ComplianceStatus.IN_PROGRESS)
        
        return {
            'module': self.name,
            'total_requirements': total,
            'passed': passed,
            'failed': failed,
            'in_progress': in_progress,
            'compliance_percentage': (passed / total * 100) if total > 0 else 0,
            'last_updated': datetime.utcnow().isoformat(),
            'requirements': {k: v.to_dict() for k, v in self.requirements.items()}
        }

class FIPS140_3(ComplianceModule):
    """FIPS 140-3 compliance module."""
    
    def initialize_requirements(self) -> None:
        """Initialize FIPS 140-3 requirements."""
        self.requirements = {
            'FIPS_140_3_SECTION_1': ComplianceRequirement(
                id='FIPS_140_3_SECTION_1',
                name='Cryptographic Module Specification',
                description='The cryptographic module shall implement all the functions of an approved security function type.',
                category='CRYPTOGRAPHIC_MODULE_SPECIFICATION',
                level=ComplianceLevel.VALIDATED,
                status=ComplianceStatus.NOT_STARTED,
                controls=[
                    {'id': 'FIPS_140_3_1.1', 'description': 'Module Specification'},
                    {'id': 'FIPS_140_3_1.2', 'description': 'Module Interfaces'},
                ]
            ),
            'FIPS_140_3_SECTION_2': ComplianceRequirement(
                id='FIPS_140_3_SECTION_2',
                name='Cryptographic Module Ports and Interfaces',
                description='The cryptographic module shall provide a set of interfaces for input, output, control, and status.',
                category='PORTS_AND_INTERFACES',
                level=ComplianceLevel.VALIDATED,
                status=ComplianceStatus.NOT_STARTED,
                controls=[
                    {'id': 'FIPS_140_3_2.1', 'description': 'Physical Ports and Interfaces'},
                    {'id': 'FIPS_140_3_2.2', 'description': 'Logical Interfaces'},
                ]
            ),
            # Add more FIPS 140-3 requirements as needed
        }

class CommonCriteria(ComplianceModule):
    """Common Criteria (ISO/IEC 15408) compliance module."""
    
    def initialize_requirements(self) -> None:
        """Initialize Common Criteria requirements."""
        self.requirements = {
            'CC_APEX_1': ComplianceRequirement(
                id='CC_APEX_1',
                name='Security Audit',
                description='The TSF shall be able to create, maintain, and protect from modification and unauthorized access or destruction an audit trail of security-relevant events.',
                category='SECURITY_AUDIT',
                level=ComplianceLevel.CERTIFIED,
                status=ComplianceStatus.NOT_STARTED,
                controls=[
                    {'id': 'FAU_GEN.1', 'description': 'Audit Data Generation'},
                    {'id': 'FAU_GEN.2', 'description': 'User Identity Association'},
                ]
            ),
            'CC_APEX_2': ComplianceRequirement(
                id='CC_APEX_2',
                name='Cryptographic Support',
                description='The TSF shall perform cryptographic key management and cryptographic operations in accordance with specified cryptographic algorithms and key sizes.',
                category='CRYPTOGRAPHIC_SUPPORT',
                level=ComplianceLevel.CERTIFIED,
                status=ComplianceStatus.NOT_STARTED,
                controls=[
                    {'id': 'FCS_CKM.1', 'description': 'Cryptographic Key Generation'},
                    {'id': 'FCS_COP.1', 'description': 'Cryptographic Operation'},
                ]
            ),
            # Add more Common Criteria requirements as needed
        }

class SecurityAudit:
    """Security audit functionality for compliance verification."""
    
    name = "SecurityAudit"
    
    def __init__(self):
        self.logger = logging.getLogger("scrambled_eggs.compliance.audit")
        self.audit_log = []
        self.audit_file = None
        self.audit_enabled = True
    
    def log_event(
        self,
        event_type: str,
        status: str,
        description: str,
        user: str = None,
        target: str = None,
        metadata: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Log a security event."""
        if not self.audit_enabled:
            return {}
        
        event = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_id': hashlib.sha256(f"{datetime.utcnow().timestamp()}{event_type}{status}".encode()).hexdigest(),
            'event_type': event_type,
            'status': status,
            'description': description,
            'user': user,
            'target': target,
            'metadata': metadata or {},
            'host': platform.node(),
            'process_id': os.getpid()
        }
        
        self.audit_log.append(event)
        
        # Write to audit file if configured
        if self.audit_file:
            try:
                with open(self.audit_file, 'a') as f:
                    f.write(json.dumps(event) + '\n')
            except Exception as e:
                self.logger.error(f"Failed to write to audit log: {str(e)}")
        
        return event
    
    def get_events(
        self,
        start_time: datetime = None,
        end_time: datetime = None,
        event_type: str = None,
        status: str = None,
        user: str = None,
        target: str = None,
        limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """Retrieve security events matching the specified criteria."""
        results = []
        
        for event in reversed(self.audit_log):
            # Apply filters
            if start_time and datetime.fromisoformat(event['timestamp']) < start_time:
                continue
            if end_time and datetime.fromisoformat(event['timestamp']) > end_time:
                continue
            if event_type and event['event_type'] != event_type:
                continue
            if status and event['status'] != status:
                continue
            if user and event.get('user') != user:
                continue
            if target and event.get('target') != target:
                continue
            
            results.append(event)
            
            if len(results) >= limit:
                break
        
        return results
    
    def generate_report(
        self,
        start_time: datetime = None,
        end_time: datetime = None,
        output_format: str = 'json',
        output_file: str = None
    ) -> str:
        """Generate a security audit report."""
        events = self.get_events(start_time, end_time)
        
        report = {
            'report_id': hashlib.sha256(datetime.utcnow().isoformat().encode()).hexdigest(),
            'generated_at': datetime.utcnow().isoformat(),
            'time_range': {
                'start': start_time.isoformat() if start_time else None,
                'end': end_time.isoformat() if end_time else None
            },
            'event_count': len(events),
            'events': events,
            'summary': self._generate_summary(events)
        }
        
        if output_format.lower() == 'json':
            report_str = json.dumps(report, indent=2)
        else:
            # Default to text format
            report_str = f"Security Audit Report\n"
            report_str += f"Generated at: {report['generated_at']}\n"
            report_str += f"Time range: {report['time_range']['start']} to {report['time_range']['end']}\n"
            report_str += f"Total events: {report['event_count']}\n\n"
            
            for event in events[:100]:  # Limit to first 100 events in text format
                report_str += f"[{event['timestamp']}] {event['event_type']} - {event['status']}: {event['description']}\n"
        
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write(report_str)
                self.logger.info(f"Audit report written to {output_file}")
            except Exception as e:
                self.logger.error(f"Failed to write audit report: {str(e)}")
        
        return report_str
    
    def _generate_summary(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate a summary of security events."""
        summary = {
            'total_events': len(events),
            'event_types': {},
            'status_counts': {},
            'users': {},
            'targets': {}
        }
        
        for event in events:
            # Count event types
            summary['event_types'][event['event_type']] = summary['event_types'].get(event['event_type'], 0) + 1
            
            # Count statuses
            summary['status_counts'][event['status']] = summary['status_counts'].get(event['status'], 0) + 1
            
            # Count users
            if 'user' in event and event['user']:
                summary['users'][event['user']] = summary['users'].get(event['user'], 0) + 1
            
            # Count targets
            if 'target' in event and event['target']:
                summary['targets'][event['target']] = summary['targets'].get(event['target'], 0) + 1
        
        return summary

class ComplianceManager:
    """Manages compliance with various standards and regulations."""
    
    def __init__(self):
        self.modules: Dict[str, ComplianceModule] = {}
        self.audit = SecurityAudit()
        self.logger = logging.getLogger("scrambled_eggs.compliance.manager")
    
    def register_module(self, module: ComplianceModule) -> None:
        """Register a compliance module."""
        self.modules[module.name] = module
        self.logger.info(f"Registered compliance module: {module.name}")
    
    def get_module(self, module_name: str) -> Optional[ComplianceModule]:
        """Get a compliance module by name."""
        return self.modules.get(module_name)
    
    def get_status(self) -> Dict[str, Any]:
        """Get the overall compliance status."""
        status = {
            'modules': {},
            'summary': {
                'total_modules': len(self.modules),
                'total_requirements': 0,
                'passed_requirements': 0,
                'failed_requirements': 0,
                'in_progress_requirements': 0,
                'compliance_percentage': 0,
                'last_updated': datetime.utcnow().isoformat()
            }
        }
        
        # Collect status from all modules
        for name, module in self.modules.items():
            module_status = module.get_status()
            status['modules'][name] = module_status
            
            # Update summary
            status['summary']['total_requirements'] += module_status['total_requirements']
            status['summary']['passed_requirements'] += module_status['passed']
            status['summary']['failed_requirements'] += module_status['failed']
            status['summary']['in_progress_requirements'] += module_status['in_progress']
        
        # Calculate overall compliance percentage
        if status['summary']['total_requirements'] > 0:
            status['summary']['compliance_percentage'] = (
                status['summary']['passed_requirements'] / 
                status['summary']['total_requirements'] * 100
            )
        
        return status
    
    def verify_all(self) -> Dict[str, Any]:
        """Verify all compliance requirements."""
        results = {}
        
        for name, module in self.modules.items():
            self.logger.info(f"Verifying compliance for module: {name}")
            
            for req_id in module.requirements:
                result = module.verify_requirement(req_id)
                results[f"{name}.{req_id}"] = {
                    'status': module.requirements[req_id].status.value,
                    'verified': result,
                    'last_verified': module.requirements[req_id].last_verified.isoformat() if module.requirements[req_id].last_verified else None
                }
                
                # Log the verification result
                self.audit.log_event(
                    event_type='COMPLIANCE_VERIFICATION',
                    status='success' if result else 'failed',
                    description=f"Verified compliance requirement: {name}.{req_id}",
                    metadata={
                        'module': name,
                        'requirement': req_id,
                        'status': module.requirements[req_id].status.value
                    }
                )
        
        return results
    
    def generate_report(self, output_format: str = 'json', output_file: str = None) -> str:
        """Generate a compliance report."""
        status = self.get_status()
        
        if output_format.lower() == 'json':
            report = json.dumps(status, indent=2)
        else:
            # Text format
            report = "Compliance Report\n"
            report += "=" * 80 + "\n\n"
            report += f"Generated at: {status['summary']['last_updated']}\n"
            report += f"Total modules: {status['summary']['total_modules']}\n"
            report += f"Total requirements: {status['summary']['total_requirements']}\n"
            report += f"Passed: {status['summary']['passed_requirements']}\n"
            report += f"Failed: {status['summary']['failed_requirements']}\n"
            report += f"In Progress: {status['summary']['in_progress_requirements']}\n"
            report += f"Compliance: {status['summary']['compliance_percentage']:.2f}%\n\n"
            
            # Add module details
            for module_name, module_status in status['modules'].items():
                report += f"Module: {module_name}\n"
                report += f"  - Status: {module_status['compliance_percentage']:.2f}% compliant\n"
                report += f"  - Requirements: {module_status['passed']} passed, {module_status['failed']} failed, {module_status['in_progress']} in progress\n\n"
                # Add requirement details
                for req_id, req in module_status['requirements'].items():
                    report += f"    - {req_id}: {req['name']} - {req['status']}\n"
        
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write(report)
                self.logger.info(f"Compliance report written to {output_file}")
            except Exception as e:
                self.logger.error(f"Failed to write compliance report: {str(e)}")
        
        return report
