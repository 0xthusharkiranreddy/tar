// OUs where you have GenericAll (enables linking a malicious GPO)
// When to run: alongside gpo_controllers.cypher; this is the second half of the GPO-inject path
// Produces predicate: ou_writable
MATCH (u)-[:GenericAll|WriteDacl]->(ou:OU)
RETURN u.samaccountname AS attacker, ou.name AS ou, ou.distinguishedname AS dn
