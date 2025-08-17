import re
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass
from enum import Enum

class ValidationResult:
    def __init__(self):
        self.is_valid = True
        self.errors = []
        self.warnings = []
    
    def add_error(self, field: str, message: str):
        self.is_valid = False
        self.errors.append(f"{field}: {message}")
    
    def add_warning(self, field: str, message: str):
        self.warnings.append(f"{field}: {message}")

class FieldType(Enum):
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    EMAIL = "email"
    PHONE = "phone"
    UUID = "uuid"
    TIMESTAMP = "timestamp"
    IP_ADDRESS = "ip_address"

@dataclass
class FieldConstraint:
    field_name: str
    field_type: FieldType
    required: bool = True
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    min_value: Optional[Union[int, float]] = None
    max_value: Optional[Union[int, float]] = None
    pattern: Optional[str] = None
    allowed_values: Optional[List[Any]] = None

class HardConstraintValidator:
    def __init__(self):
        # Regex patterns for common formats
        self.patterns = {
            'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
            'phone': r'^\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}$',
            'uuid': r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
            'ip_v4': r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
            'ip_v6': r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
        }
        
        # Define schema for account opening fraud (example)
        self.account_opening_schema = [
            FieldConstraint("user_id", FieldType.UUID, required=True),
            FieldConstraint("email", FieldType.EMAIL, required=True),
            FieldConstraint("phone", FieldType.PHONE, required=False),
            FieldConstraint("first_name", FieldType.STRING, required=True, min_length=1, max_length=50),
            FieldConstraint("last_name", FieldType.STRING, required=True, min_length=1, max_length=50),
            FieldConstraint("address", FieldType.STRING, required=True, min_length=10, max_length=200),
            FieldConstraint("ip_address", FieldType.IP_ADDRESS, required=True),
            FieldConstraint("device_fingerprint", FieldType.STRING, required=True, min_length=32, max_length=64),
            FieldConstraint("timestamp", FieldType.TIMESTAMP, required=True),
            FieldConstraint("account_type", FieldType.STRING, required=True, 
                          allowed_values=["personal", "business", "premium"]),
            FieldConstraint("fraud_score", FieldType.FLOAT, required=False, min_value=0.0, max_value=1.0),
            FieldConstraint("is_fraud", FieldType.BOOLEAN, required=True),
            FieldConstraint("velocity_1h", FieldType.INTEGER, required=False, min_value=0, max_value=1000),
            FieldConstraint("velocity_24h", FieldType.INTEGER, required=False, min_value=0, max_value=10000)
        ]
    
    def validate_field_type(self, value: Any, field_type: FieldType) -> bool:
        """Validate that a value matches the expected type"""
        if value is None:
            return True  
        
        if field_type == FieldType.STRING:
            return isinstance(value, str)
        elif field_type == FieldType.INTEGER:
            return isinstance(value, int)
        elif field_type == FieldType.FLOAT:
            return isinstance(value, (int, float))
        elif field_type == FieldType.BOOLEAN:
            return isinstance(value, bool)
        elif field_type == FieldType.EMAIL:
            return isinstance(value, str) and re.match(self.patterns['email'], value) is not None
        elif field_type == FieldType.PHONE:
            return isinstance(value, str) and re.match(self.patterns['phone'], value) is not None
        elif field_type == FieldType.UUID:
            return isinstance(value, str) and re.match(self.patterns['uuid'], value.lower()) is not None
        elif field_type == FieldType.TIMESTAMP:
            if isinstance(value, str):
                try:
                    datetime.fromisoformat(value.replace('Z', '+00:00'))
                    return True
                except ValueError:
                    return False
            return isinstance(value, datetime)
        elif field_type == FieldType.IP_ADDRESS:
            return isinstance(value, str) and (
                re.match(self.patterns['ip_v4'], value) is not None or
                re.match(self.patterns['ip_v6'], value) is not None
            )
        
        return False
    
    def validate_field_constraints(self, value: Any, constraint: FieldConstraint) -> List[str]:
        """Validate a single field against its constraints"""
        errors = []
        
        if value is None:
            if constraint.required:
                errors.append(f"Required field is missing")
            return errors
        
        # Type validation
        if not self.validate_field_type(value, constraint.field_type):
            errors.append(f"Invalid type. Expected {constraint.field_type.value}")
            return errors  
        
        # String length constraints
        if constraint.field_type in [FieldType.STRING, FieldType.EMAIL, FieldType.PHONE] and isinstance(value, str):
            if constraint.min_length is not None and len(value) < constraint.min_length:
                errors.append(f"Too short. Minimum length: {constraint.min_length}")
            if constraint.max_length is not None and len(value) > constraint.max_length:
                errors.append(f"Too long. Maximum length: {constraint.max_length}")
        
        # Numeric value constraints
        if constraint.field_type in [FieldType.INTEGER, FieldType.FLOAT] and isinstance(value, (int, float)):
            if constraint.min_value is not None and value < constraint.min_value:
                errors.append(f"Value too small. Minimum: {constraint.min_value}")
            if constraint.max_value is not None and value > constraint.max_value:
                errors.append(f"Value too large. Maximum: {constraint.max_value}")
        
        # Pattern matching
        if constraint.pattern is not None and isinstance(value, str):
            if not re.match(constraint.pattern, value):
                errors.append(f"Does not match required pattern: {constraint.pattern}")
        
        # Allowed values
        if constraint.allowed_values is not None:
            if value not in constraint.allowed_values:
                errors.append(f"Invalid value. Allowed: {constraint.allowed_values}")
        
        return errors
    
    def validate_business_rules(self, record: Dict[str, Any]) -> List[str]:
        """Validate business logic constraints"""
        errors = []
        
        
        
        # Rule 1: Fraud score should align with is_fraud flag
        if 'fraud_score' in record and 'is_fraud' in record:
            fraud_score = record['fraud_score']
            is_fraud = record['is_fraud']
            if fraud_score is not None and is_fraud is not None:
                if is_fraud and fraud_score < 0.5:
                    errors.append("Business rule violation: fraud_score should be >= 0.5 when is_fraud=True")
                elif not is_fraud and fraud_score > 0.3:
                    errors.append("Business rule violation: fraud_score should be <= 0.3 when is_fraud=False")
        
        # Rule 2: Velocity constraints
        if 'velocity_1h' in record and 'velocity_24h' in record:
            vel_1h = record.get('velocity_1h', 0)
            vel_24h = record.get('velocity_24h', 0)
            if vel_1h is not None and vel_24h is not None and vel_1h > vel_24h:
                errors.append("Business rule violation: velocity_1h cannot exceed velocity_24h")
        
        # Rule 3: Timestamp should be reasonable (not too far in future/past)
        if 'timestamp' in record:
            timestamp = record['timestamp']
            if isinstance(timestamp, str):
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    now = datetime.now()
                    if dt > now:
                        errors.append("Business rule violation: timestamp cannot be in the future")
                    if (now - dt).days > 365 * 5:  # More than 5 years old
                        errors.append("Business rule violation: timestamp is too old (>5 years)")
                except ValueError:
                    pass  # Type validation will catch this
        
        # Rule 4: Email domain should not be obviously fake
        if 'email' in record:
            email = record.get('email', '')
            if isinstance(email, str):
                suspicious_domains = ['test.com', 'example.com', 'fake.com', 'temp.com']
                domain = email.split('@')[-1].lower() if '@' in email else ''
                if domain in suspicious_domains:
                    errors.append(f"Business rule violation: suspicious email domain '{domain}'")
        
        return errors
    
    def validate_record(self, record: Dict[str, Any], schema: List[FieldConstraint] = None) -> ValidationResult:
        """Validate a single fraud record against the schema and business rules"""
        if schema is None:
            schema = self.account_opening_schema
        
        result = ValidationResult()
        
        # Check required fields and validate each field
        for constraint in schema:
            field_value = record.get(constraint.field_name)
            
            # Validate field constraints
            field_errors = self.validate_field_constraints(field_value, constraint)
            for error in field_errors:
                result.add_error(constraint.field_name, error)
        
        # Check for unexpected fields
        schema_fields = {c.field_name for c in schema}
        for field_name in record.keys():
            if field_name not in schema_fields:
                result.add_warning(field_name, "Unexpected field not in schema")
        
        # Validate business rules
        business_rule_errors = self.validate_business_rules(record)
        for error in business_rule_errors:
            result.add_error("business_rules", error)
        
        return result
    
    def validate_batch(self, records: List[Dict[str, Any]], schema: List[FieldConstraint] = None) -> Dict[str, Any]:
        """Validate a batch of records and return summary statistics"""
        if not records:
            return {"error": "Empty batch provided"}
        
        results = []
        total_errors = 0
        total_warnings = 0
        
        for i, record in enumerate(records):
            result = self.validate_record(record, schema)
            results.append({
                "record_index": i,
                "is_valid": result.is_valid,
                "errors": result.errors,
                "warnings": result.warnings
            })
            total_errors += len(result.errors)
            total_warnings += len(result.warnings)
        
        valid_count = sum(1 for r in results if r["is_valid"])
        
        return {
            "total_records": len(records),
            "valid_records": valid_count,
            "invalid_records": len(records) - valid_count,
            "total_errors": total_errors,
            "total_warnings": total_warnings,
            "validation_rate": valid_count / len(records),
            "results": results
        }

# Example usage and testing
if __name__ == "__main__":
    validator = HardConstraintValidator()
    
    # Test with valid record
    valid_record = {
        "user_id": "550e8400-e29b-41d4-a716-446655440000",
        "email": "john.doe@example.com",
        "phone": "+1-555-123-4567",
        "first_name": "John",
        "last_name": "Doe",
        "address": "123 Main St, Anytown, USA",
        "ip_address": "192.168.1.1",
        "device_fingerprint": "abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567",
        "timestamp": "2025-08-17T10:30:00Z",
        "account_type": "personal",
        "fraud_score": 0.1,
        "is_fraud": False,
        "velocity_1h": 1,
        "velocity_24h": 5
    }
    
    # Test with invalid record
    invalid_record = {
        "user_id": "invalid-uuid",
        "email": "not-an-email",
        "first_name": "",  # Too short
        "last_name": "Doe",
        "address": "123 Main St, Anytown, USA",
        "ip_address": "999.999.999.999",  # Invalid IP
        "device_fingerprint": "short",  # Too short
        "timestamp": "invalid-date",
        "account_type": "invalid_type",  # Not in allowed values
        "fraud_score": 1.5,  # Out of range
        "is_fraud": True,  # Conflicts with low fraud_score
        "velocity_1h": 10,
        "velocity_24h": 5  # Business rule violation
    }
    
    print("=== Testing Valid Record ===")
    result = validator.validate_record(valid_record)
    print(f"Valid: {result.is_valid}")
    print(f"Errors: {result.errors}")
    print(f"Warnings: {result.warnings}")
    
    print("\n=== Testing Invalid Record ===")
    result = validator.validate_record(invalid_record)
    print(f"Valid: {result.is_valid}")
    print(f"Errors: {result.errors}")
    print(f"Warnings: {result.warnings}")
    
    print("\n=== Testing Batch Validation ===")
    batch_result = validator.validate_batch([valid_record, invalid_record])
    print(f"Batch validation rate: {batch_result['validation_rate']:.2%}")
    print(f"Total errors: {batch_result['total_errors']}")
    print(f"Total warnings: {batch_result['total_warnings']}")
