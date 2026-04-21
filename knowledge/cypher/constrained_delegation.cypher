// Principals with constrained delegation (msDS-AllowedToDelegateTo set)
// When to run: after initial cred; identify S4U → impersonation candidates
// Produces predicate: constrained_delegation_found
MATCH (n)-[:AllowedToDelegate]->(t:Computer)
RETURN n.name AS source, collect(t.name) AS targets
