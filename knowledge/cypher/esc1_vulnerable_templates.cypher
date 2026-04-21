// ADCS ESC1 candidates: templates with ENROLLEE_SUPPLIES_SUBJECT + CLIENT_AUTH EKU + low enrollment rights
// When to run: after BloodHound with ADCS collector (certipy → bloodhound merge)
// Produces predicate: esc1_templates_found
MATCH (t:GPO)-[:Enroll]->(p)
WHERE t.enrolleesuppliessubject = true
  AND t.authenticationenabled = true
  AND t.requiresmanagerapproval = false
RETURN t.name AS template, collect(p.samaccountname) AS can_enroll
