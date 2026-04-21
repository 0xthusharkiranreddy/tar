// Shortest paths from owned principals to any high-value target
// When to run: after ingesting owned status (SharpHound --Owned or BH manual mark)
// Produces predicate: shortest_path_to_dx_identified
MATCH (o {owned: true}), (t {highvalue: true}), p = shortestPath((o)-[*1..6]->(t))
WHERE o <> t
RETURN o.samaccountname AS start, t.name AS end, length(p) AS hops, [n IN nodes(p) | n.name] AS path
ORDER BY hops ASC
LIMIT 25
