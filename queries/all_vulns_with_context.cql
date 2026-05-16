MATCH (v:Vulnerability)-[:EXISTS_IN]->(p:Package)-[:INSTALLED_ON]->(a:Asset)
OPTIONAL MATCH (v)-[:HAS]->(t:ThreatSignal)
WITH v, t,
     COLLECT(DISTINCT a.network_exposure) AS exposures,
     COLLECT(DISTINCT a.tier) AS tiers,
     COUNT(DISTINCT a) AS n_assets
RETURN
  v.name AS cve_id,
  v.cvss AS cvss,
  v.description AS description,
  t.epss AS epss,
  t.kevListed AS kev,
  t.publicExploit AS public_exploit,
  exposures,
  tiers,
  n_assets