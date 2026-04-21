// Kerberoastable users (have an SPN set, no pre-auth required for TGS)
// When to run: any time after ingesting BloodHound data; before kerberoast attacks
// Produces predicate: kerberoastable_users_found
MATCH (u:User {hasspn: true})
WHERE NOT u.samaccountname ENDS WITH '$'
RETURN u.samaccountname AS user, u.serviceprincipalnames AS spns, u.pwdlastset AS pwdage
ORDER BY u.pwdlastset ASC
