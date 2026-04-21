// Foreign security principals in high-value groups (cross-trust access)
// When to run: trust analysis; identifies members who came from another forest
// Produces predicate: foreign_principals_in_high_value
MATCH (u)-[:MemberOf*1..]->(g:Group)
WHERE g.highvalue = true AND u.domain <> g.domain
RETURN u.samaccountname AS principal, u.domain AS from_domain, g.name AS group, g.domain AS group_domain
