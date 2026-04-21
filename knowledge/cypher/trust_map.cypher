// Domain trust topology — direction, transitivity, SID-filter status
// When to run: early AD recon; defines inter-forest attack paths (SIDHistory, trust-key forge)
// Produces predicate: trusts_mapped
MATCH (a:Domain)-[r:TrustedBy]->(b:Domain)
RETURN a.name AS from_domain, b.name AS to_domain, r.trusttype AS type, r.sidfiltering AS sidfilter
