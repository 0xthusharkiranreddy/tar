// Computers with unconstrained delegation (trusted for delegation)
// When to run: early AD enum; these are relay targets for coerce → delegation → DA
// Produces predicate: unconstrained_delegation_hosts_found
MATCH (c:Computer {unconstraineddelegation: true})
WHERE NOT c.name ENDS WITH 'DC'
RETURN c.name AS computer, c.operatingsystem AS os
