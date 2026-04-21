// RBCD candidates: computers where any domain user has GenericWrite/WriteAccountRestrictions
// When to run: when you have any domain user cred; seeds RBCD via machine account
// Produces predicate: rbcd_writable_computers
MATCH (u:User)-[r:GenericWrite|GenericAll|WriteDacl|Owns|AddKeyCredentialLink|WriteAccountRestrictions]->(c:Computer)
RETURN u.samaccountname AS attacker, type(r) AS edge, c.name AS victim_computer
