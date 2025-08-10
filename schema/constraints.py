ACCOUNT_OPENING_CONSTRAINTS = {
  "temporal_constraints": [
        {
            "name": "registration_not_future", 
            "rule": "registration_timestamp <= current_time",
            "explanation": "Account can't be created in the future"
        },
        {
            "name": "registration_not_too_old",
            "rule": "registration_timestamp >= 2020-01-01", 
            "explanation": "Will only simulate recent account openings"
        }
    ],
    
    "geographic_constraints": [
        {
            "name": "phone_country_match",
            "rule": "if address.country == 'US' then phone starts with '+1'",
            "explanation": "US addresses should have US phone numbers"
        },
        {
            "name": "ip_country_reasonable", 
            "rule": "ip_address location within 500 miles of address.country",
            "explanation": "IP location should be reasonably close to stated address"
        }
    ],
    
    "format_constraints": 
        {
            "name": "name_not_obviously_fake",
            "rule": "full_name not in ['Test User']",
            "explanation": "Avoid obviously placeholder names"
        }
}
