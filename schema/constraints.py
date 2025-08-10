ACCOUNT_OPENING_CONSTRAINTS = {
    "identity_constraints": [
        {
            "name": "age_minimum",
            "rule": "age >= 18",
            "explanation": "Account holder must be an adult"
        },
        {
            "name": "name_not_placeholder",
            "rule": "full_name not in ['Test User', 'John Doe', 'Jane Smith']",
            "explanation": "Avoid obviously placeholder names"
        },
        {
            "name": "address_looks_real",
            "rule": "address.street not in ['123 Main St', '123 Fake Street', 'N/A']",
            "explanation": "Avoid obviously fake addresses"
        }
    ],
    
    "contact_constraints": [
        {
            "name": "email_not_disposable",
            "rule": "email_domain not in ['10minutemail.com', 'guerrillamail.com', 'tempmail.org']",
            "explanation": "Block common temporary email services"
        },
        {
            "name": "email_format_reasonable",
            "rule": "email username != phone_number and email != 'test@test.com'",
            "explanation": "Email should look like real personal email"
        },
        {
            "name": "phone_format_consistent",
            "rule": "phone_country_code matches address.country",
            "explanation": "Phone country should match address country"
        }
    ],
    
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
    ]
}
