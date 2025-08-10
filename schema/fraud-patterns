ACCOUNT_OPENING_FRAUD_PATTERNS = {
    
    "synthetic_identity": {
        "description": "Fake person created by mixing real and fake information",
        "real_world_example": "Take real SSN + fake name + fake address",
        "key_indicators": [
            "ssn_name_mismatch",
            "new_credit_profile", 
            "address_not_residential",
            "phone_number_new"
        ],
        "typical_data_patterns": {
            "credit_score": "thin_file_or_none",
            "address_type": "commercial_or_fake", 
            "phone_age": "less_than_30_days",
            "email_domain": "new_or_suspicious"
        }
    },
    
    "account_farming": {
        "description": "Opening many accounts quickly from same source",
        "real_world_example": "One person opens 50 accounts in 1 hour",
        "key_indicators": [
            "high_velocity_same_ip",
            "device_reuse",
            "similar_registration_times",
            "sequential_email_patterns"
        ],
        "typical_data_patterns": {
            "accounts_per_ip": "10_to_100_per_hour",
            "device_fingerprint": "reused_across_accounts", 
            "registration_timing": "burst_pattern",
            "email_pattern": "sequential_or_generated"
        }
    },
    
    "stolen_identity": {
        "description": "Using real person's information without permission", 
        "real_world_example": "Fraudster has victim's real SSN, name, address",
        "key_indicators": [
            "device_location_mismatch",
            "behavioral_anomaly",
            "contact_info_changed",
            "unusual_access_pattern"
        ],
        "typical_data_patterns": {
            "identity_info": "legitimate_but_compromised",
            "device_location": "different_from_historical", 
            "contact_changes": "recent_phone_email_updates",
            "access_timing": "unusual_hours_or_frequency"
        }
    }
}
