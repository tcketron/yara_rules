rule Base64_Encoded_Email 
{ 
    meta: 
        author         = "Tanner Ketron" 
        description    = "Detects base64-encoded email addresses across any file." 
        created_date   = "2025-02-13" 
        updated_date   = "2025-02-13" 
        reference      = "Base64 encoding of emails can indicate obfuscation techniques used in phishing, malware, or data exfiltration." 

    strings: 
        // Base64 patterns for common email structures (username@domain.tld)
        $b64_email_1 = /[A-Za-z0-9+\/=]{6,}@[A-Za-z0-9+\/=]{3,}\.[A-Za-z0-9+\/=]{2,6}/
        $b64_email_2 = /[A-Za-z0-9+\/=]{10,}@[A-Za-z0-9+\/=]{5,}\.[A-Za-z0-9+\/=]{2,4}/
        $b64_email_3 = /[A-Za-z0-9+\/=]{8,}@[A-Za-z0-9+\/=]{4,}\.(com|net|org|gov|edu|io|xyz|info)/

    condition: 
        any of them
}
