// AS-REP roastable users (DONT_REQ_PREAUTH flag set)
// When to run: on any domain where you have LDAP read (any domain user cred)
// Produces predicate: asreproastable_users_found
MATCH (u:User {dontreqpreauth: true})
WHERE u.enabled = true
RETURN u.samaccountname AS user, u.enabled AS enabled, u.pwdlastset AS pwdage
