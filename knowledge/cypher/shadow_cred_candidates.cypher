// Shadow Credentials candidates (AddKeyCredentialLink write path)
// When to run: after initial cred; produces PKINIT-auth path without password change
// Produces predicate: shadow_cred_writable_principals
MATCH p=(u)-[:AddKeyCredentialLink]->(v)
RETURN u.samaccountname AS attacker, v.name AS victim
