from typing import Dict, Any, Tuple, List
from enum import Enum

class DifficultyTier(Enum):
    """Difficulty tiers"""
    T1_PLAUSIBLE = "T1"      # Easy to detect
    T2_EVASIVE = "T2"        # Harder to detect  
    T3_ADVERSARIAL = "T3"    # Hardest

# Base parameter ranges for account opening fraud
FRAUD_PARAMS = {
    
    # VELOCITY PATTERNS
    "velocity": {
        "accounts_per_hour": {
            "T1": (10, 50),      # Obviously suspicious volume
            "T2": (3, 10),       # Moderate suspicious volume
            "T3": (1, 3)         # Just above normal but sustained
        },
        "accounts_per_ip": {
            "T1": (20, 100),     # Many accounts from same IP
            "T2": (5, 20),       # Several accounts from same IP
            "T3": (2, 5)         # Just a few accounts per IP
        },
        "accounts_per_device": {
            "T1": (15, 50),      # Device farming obvious
            "T2": (3, 15),       # Some device reuse
            "T3": (2, 3)         # Minimal device reuse
        }
    },
    
    # TEMPORAL PATTERNS
    "temporal": {
        "registration_burst_duration": {
            "T1": (60, 300),     # 1-5 minutes (very obvious burst)
            "T2": (300, 1800),   # 5-30 minutes (moderate burst)
            "T3": (1800, 7200)   # 30min-2hours (spread out)
        },
        "inter_registration_gap": {
            "T1": (5, 30),       # 5-30 seconds between registrations
            "T2": (30, 300),     # 30sec-5min between registrations
            "T3": (300, 3600)    # 5min-1hour between registrations
        },
        "time_of_day_clustering": {
            "T1": (0.8, 1.0),    # 80-100% of registrations in 2-hour window
            "T2": (0.5, 0.8),    # 50-80% clustered
            "T3": (0.3, 0.5)     # 30-50% clustered (more natural)
        }
    },
    
    # DEVICE/FINGERPRINT PATTERNS 
    "device_patterns": {
        "device_reuse_rate": {
            "T1": (0.7, 0.9),    # 70-90% of accounts share devices
            "T2": (0.3, 0.7),    # 30-70% share devices
            "T3": (0.1, 0.3)     # 10-30% share devices
        },
        "user_agent_diversity": {
            "T1": (1, 3),        # 1-3 different user agents total
            "T2": (3, 10),       # 3-10 different user agents
            "T3": (10, 50)       # 10-50 different user agents
        },
        "screen_resolution_diversity": {
            "T1": (1, 2),        # 1-2 screen resolutions
            "T2": (2, 5),        # 2-5 screen resolutions
            "T3": (5, 15)        # 5-15 screen resolutions
        }
    },
    
    # NETWORK/IP PATTERNS 
    "network_patterns": {
        "ip_subnet_clustering": {
            "T1": (0.8, 1.0),    # 80-100% from same /24 subnet
            "T2": (0.4, 0.8),    # 40-80% from same subnet
            "T3": (0.1, 0.4)     # 10-40% from same subnet
        },
        "proxy_vpn_usage_rate": {
            "T1": (0.8, 1.0),    # 80-100% using proxies/VPNs
            "T2": (0.3, 0.8),    # 30-80% using proxies/VPNs
            "T3": (0.1, 0.3)     # 10-30% using proxies/VPNs
        },
        "geolocation_consistency": {
            "T1": (0.1, 0.3),    # 10-30% consistent geo (suspicious)
            "T2": (0.3, 0.7),    # 30-70% consistent geo
            "T3": (0.7, 0.9)     # 70-90% consistent geo (more natural)
        }
    },
    
    # IDENTITY PATTERNS
    "identity_patterns": {
        "synthetic_identity_rate": {
            "T1": (0.8, 1.0),    # 80-100% synthetic identities
            "T2": (0.4, 0.8),    # 40-80% synthetic identities
            "T3": (0.1, 0.4)     # 10-40% synthetic identities
        },
        "pii_field_consistency": {
            "T1": (0.2, 0.5),    # 20-50% of PII fields match (inconsistent)
            "T2": (0.5, 0.8),    # 50-80% of PII fields match
            "T3": (0.8, 0.95)    # 80-95% of PII fields match (looks real)
        },
        "email_phone_mismatch_rate": {
            "T1": (0.6, 0.9),    # 60-90% have mismatched email/phone patterns
            "T2": (0.2, 0.6),    # 20-60% have mismatches
            "T3": (0.05, 0.2)    # 5-20% have mismatches
        }
    },
    
    # BEHAVIORAL PATTERNS
    "behavioral_patterns": {
        "immediate_activity_rate": {
            "T1": (0.8, 1.0),    # 80-100% immediately active after registration
            "T2": (0.4, 0.8),    # 40-80% immediately active
            "T3": (0.1, 0.4)     # 10-40% immediately active (more natural)
        },
        "session_duration_variance": {
            "T1": (0.1, 0.3),    # Low variance (robotic behavior)
            "T2": (0.3, 0.7),    # Medium variance
            "T3": (0.7, 1.0)     # High variance (human-like)
        }
    }
}

FRAUD_PATTERN_CONFIGS = {
    
    "synthetic_identity": {
        "description": "Fake person with mixed real/fake credentials",
        "params": {
            "velocity.accounts_per_hour": "T2",
            "identity_patterns.synthetic_identity_rate": "T1", 
            "identity_patterns.email_phone_mismatch_rate": "T1",
            "device_patterns.device_reuse_rate": "T2",
            "network_patterns.proxy_vpn_usage_rate": "T2"
        },
        "weight": 0.3  
    },
    
    "account_farming": {
        "description": "Multiple accounts from same source rapidly",
        "params": {
            "velocity.accounts_per_hour": "T1",
            "velocity.accounts_per_ip": "T1", 
            "temporal.registration_burst_duration": "T1",
            "device_patterns.device_reuse_rate": "T1",
            "network_patterns.ip_subnet_clustering": "T1"
        },
        "weight": 0.4  
    },
    
    "sophisticated_evasion": {
        "description": "Advanced fraud with evasion techniques",
        "params": {
            "velocity.accounts_per_hour": "T3",
            "temporal.inter_registration_gap": "T3",
            "device_patterns.user_agent_diversity": "T3",
            "network_patterns.proxy_vpn_usage_rate": "T3",
            "identity_patterns.pii_field_consistency": "T3",
            "behavioral_patterns.session_duration_variance": "T3"
        },
        "weight": 0.2 
    },
    
    "dormant_sleeper": {
        "description": "Accounts that register but remain inactive initially",
        "params": {
            "velocity.accounts_per_hour": "T3",
            "behavioral_patterns.immediate_activity_rate": "T1",  # Low immediate activity
            "identity_patterns.pii_field_consistency": "T2",
            "device_patterns.device_reuse_rate": "T3"
        },
        "weight": 0.1  
    }
}

def get_param_value(pattern_name: str, param_path: str, tier_override: str = None) -> Tuple[float, float]:
    """
    Get parameter range for a specific fraud pattern and parameter.
    
    Args:
        pattern_name: Name of fraud pattern (e.g., 'synthetic_identity')
        param_path: Dot-notation path to parameter (e.g., 'velocity.accounts_per_hour')
        tier_override: Override the tier specified in pattern config
    
    Returns:
        Tuple of (min_value, max_value) for the parameter
    """
    if pattern_name not in FRAUD_PATTERN_CONFIGS:
        raise ValueError(f"Unknown fraud pattern: {pattern_name}")
    
    pattern_config = FRAUD_PATTERN_CONFIGS[pattern_name]
    
    # Get the tier for this parameter (or use override)
    if tier_override:
        tier = tier_override
    else:
        tier = pattern_config["params"].get(param_path)
        if not tier:
            raise ValueError(f"Parameter {param_path} not defined for pattern {pattern_name}")
    
    # Navigate to the parameter in FRAUD_PARAMS
    param_parts = param_path.split('.')
    current = FRAUD_PARAMS
    
    for part in param_parts:
        if part not in current:
            raise ValueError(f"Parameter path {param_path} not found")
        current = current[part]
    
    if tier not in current:
        raise ValueError(f"Tier {tier} not found for parameter {param_path}")
    
    return current[tier]

def get_all_pattern_params(pattern_name: str) -> Dict[str, Tuple[float, float]]:
    """Get all parameter ranges for a specific fraud pattern."""
    if pattern_name not in FRAUD_PATTERN_CONFIGS:
        raise ValueError(f"Unknown fraud pattern: {pattern_name}")
    
    pattern_config = FRAUD_PATTERN_CONFIGS[pattern_name]
    result = {}
    
    for param_path, tier in pattern_config["params"].items():
        result[param_path] = get_param_value(pattern_name, param_path)
    
    return result

# Example usage and testing
if __name__ == "__main__":
    # Test getting parameter values
    print("=== Testing Parameter Retrieval ===")
    
    # Test synthetic identity pattern
    print(f"Synthetic Identity - Accounts per hour: {get_param_value('synthetic_identity', 'velocity.accounts_per_hour')}")
    print(f"Synthetic Identity - Device reuse rate: {get_param_value('synthetic_identity', 'device_patterns.device_reuse_rate')}")
    
    # Test account farming pattern  
    print(f"Account Farming - Registration burst: {get_param_value('account_farming', 'temporal.registration_burst_duration')}")
    
    # Get all params for a pattern
    print("\n=== All Parameters for Sophisticated Evasion ===")
    all_params = get_all_pattern_params('sophisticated_evasion')
    for param, range_val in all_params.items():
        print(f"{param}: {range_val}")
    
    # Test tier override
    print(f"\nOverride test - Synthetic identity with T3 velocity: {get_param_value('synthetic_identity', 'velocity.accounts_per_hour', 'T3')}")
