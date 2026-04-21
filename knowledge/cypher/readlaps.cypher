// Principals that can read LAPS (ms-Mcs-AdmPwd or msLAPS-Password)
// When to run: after initial cred; each computer's local admin password is ours if we have ReadLAPSPassword
// Produces predicate: laps_readable_computers
MATCH (u)-[:ReadLAPSPassword]->(c:Computer)
RETURN u.samaccountname AS reader, c.name AS computer
