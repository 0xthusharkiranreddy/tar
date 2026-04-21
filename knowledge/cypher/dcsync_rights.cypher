// Principals with GetChanges + GetChangesAll (DCSync rights)
// When to run: after initial foothold; finds users/groups one credential away from krbtgt dump
// Produces predicate: dcsync_rights_found
MATCH (u)-[:GetChanges]->(d:Domain)
MATCH (u)-[:GetChangesAll]->(d)
RETURN u.samaccountname AS principal, d.name AS domain
