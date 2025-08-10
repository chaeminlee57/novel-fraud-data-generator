CORE_ACCOUNT_OPENING_SCHEMA = {
    "user_id": {
        "type": "string", 
        "description": "Unique ID for the account (like a customer number)"
    },
    "full_name": {
        "type": "string",
        "description": "The person's full name"
    },
    "email": {
        "type": "string",
        "format": "email",
        "description": "Email address"
    },
    "phone": {
        "type": "string", 
        "description": "Phone number"
    }
}
