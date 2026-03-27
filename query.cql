//TODO: Optimize query
// 1. create constraints
// 2. Create indexes

// 1. Load the assets
CALL json_util.load_from_path("/data/cmdb_assets.json")
YIELD objects as obj
UNWIND obj AS data
UNWIND data.assets as asset

// Create the asset nodes
MERGE (a:Asset {name: asset.assetId, hostname: asset.hostname})

WITH count(*) AS dummy

// 2. Load scanner results
CALL json_util.load_from_path("/data/scanner_results.sarif.json")
YIELD objects as obj
UNWIND obj AS data

// Create vulnerability instance nodes
UNWIND data.runs AS run
UNWIND run.tool.driver.rules AS rule
MERGE (v:Vulnerability {name: rule.id, cvss: toFloat(rule.properties.`security-severity`), description: rule.shortDescription.text})

WITH count(*) AS dummy

//3. Load services data
CALL json_util.load_from_path("/data/service_catalog.json")
YIELD objects as obj
UNWIND obj AS data

// Create service nodes
UNWIND data.services as service
MERGE (s:Service {name: service.service, description: service.description})

WITH count(*) AS dummy

//4. Load sbom data
CALL json_util.load_from_path("/data/sbom.spdx.json")
YIELD objects as obj
UNWIND obj AS data

// Create dependency nodes
UNWIND data.packages as package
MERGE (p:Package {name: package.name, version: package.versionInfo, spdx_id: package.SPDXID})

WITH count(*) AS dummy

// 5. Load threat intelligence data
CALL json_util.load_from_path("/data/exploit_intelligence.json")
YIELD objects
UNWIND objects as obj
UNWIND obj.vulnerabilities as vuln
CREATE (t:ThreatSignal {cve: vuln.cve, epss: vuln.epss, kevListed: toBoolean(vuln.kevListed), publicExploit: toBoolean(vuln.publicExploit)})

WITH count(*) AS dummy

// Reload files to create node relationships

// 6. Create relation between vulnerability and asset
// TODO: Optimize this query
CALL json_util.load_from_path("/data/scanner_results.sarif.json")
YIELD objects as obj
UNWIND obj AS data
UNWIND data.runs as run
UNWIND run.results as result
MATCH (v:Vulnerability)
MATCH (a:Asset)
WHERE result.properties.assetId = a.name AND result.ruleId = v.name
CREATE (v)-[:AFFECTS {level: result.level, port: toInteger(result.properties.port), scanner: result.properties.scanner}]->(a)

WITH count(*) AS dummy

// 7. Create relation between assets and services
CALL json_util.load_from_path("/data/cmdb_assets.json")
YIELD objects as obj
UNWIND obj AS data
UNWIND data.assets as asset

MATCH (a:Asset {name: asset.assetId})
MATCH (s:Service {name: asset.service})

// TODO: add relation properties
MERGE (a)-[:HOSTS]->(s)

WITH count(*) AS dummy

// 8. Create relation between asset and package
CALL json_util.load_from_path("/data/sbom.spdx.json")
YIELD objects as obj
UNWIND obj AS data
UNWIND data.relationships as relation
MATCH (a:Asset {name: substring(relation.spdxElementId, 6)})
MATCH (p:Package {spdx_id: relation.relatedSpdxElement})

// TODO: add relation properties
MERGE (a)-[:DEPENDS_ON]->(p)

WITH count(*) AS dummy

// 9. Create relation between service and service
CALL json_util.load_from_path("/data/architecture.json")
YIELD objects as obj
UNWIND obj as data
UNWIND data.dependencies as dep
MATCH (src:Service {name: dep.source})
MATCH (tgt:Service {name: dep.target})

// TODO: add relation properties
MERGE (src)-[:DEPENDS_ON]->(tgt)

WITH count(*) AS dummy

// 10. Creat threat intel relation
CALL json_util.load_from_path("/data/exploit_intelligence.json")
YIELD objects
UNWIND objects as obj
UNWIND obj.vulnerabilities as vuln
MATCH (v:Vulnerability {name: vuln.cve})
MATCH (t:ThreatSignal {cve: vuln.cve})
CREATE (v)-[:HAS]->(t)