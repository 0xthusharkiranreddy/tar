// Principals with GenericAll/GenericWrite/WriteDacl on GPOs
// When to run: after initial cred; any of these grants code exec on every host linked to the GPO
// Produces predicate: gpo_writable
MATCH (u)-[r:GenericAll|GenericWrite|WriteDacl|Owns]->(g:GPO)
RETURN u.samaccountname AS attacker, type(r) AS edge, g.name AS gpo
