// Principals that can read gMSA passwords (ReadGMSAPassword edge)
// When to run: after initial cred; gMSA accounts often highly privileged
// Produces predicate: gmsa_readable_accounts
MATCH (u)-[:ReadGMSAPassword]->(g:User)
RETURN u.samaccountname AS reader, g.samaccountname AS gmsa_account, g.enabled AS enabled
