// 1. Load the assets
CALL json_util.load_from_path("/anonymized_v4/cmdb_assets.json")
YIELD objects as obj
UNWIND obj AS data
UNWIND data.assets as asset

// Create the asset nodes
MERGE (a:Asset {
    name: asset.assetId,
    hostname: asset.hostname,
    tier: asset.serviceTier,
    environment: asset.environment,
    network_exposure: asset.networkExposure,
    data_classification: asset.dataClassification, 
    owner_team: asset.ownerTeam,
    cloud_provider: asset.cloudProvider,
    kind: asset.kind
    })

WITH count(*) AS dummy

// 2. Load scanner results
CALL json_util.load_from_path("/anonymized_v4/scanner_results.sarif.json")
YIELD objects as obj
UNWIND obj AS data

// Create vulnerability instance nodes
UNWIND data.runs AS run
UNWIND run.tool.driver.rules AS rule
WITH rule
WHERE rule.id STARTS WITH "CVE"
MERGE (v:Vulnerability {
    name: rule.id,
    cvss: toFloat(rule.properties.`security-severity`),
    description: rule.shortDescription.text
    })

WITH count(*) AS dummy

//3. Load services data
CALL json_util.load_from_path("/anonymized_v4/service_catalog.json")
YIELD objects as obj
UNWIND obj AS data

// Create service nodes
UNWIND data.services as service
MERGE (s:Service {
    name: service.service,
    description: service.description,
    handles_pii: toBoolean(service.handlesPII),
    revenue_impact: service.revenueImpact,
    criticality: service.criticality
    })

WITH count(*) AS dummy

// Append service docs to service nodes
CALL json_util.load_from_path("/anonymized_v4/service_docs.json")
YIELD objects as obj
UNWIND obj AS data
UNWIND data.documents as doc

MATCH (s:Service {name: doc.service})
SET s.documentation = doc.text

WITH count(*) AS dummy

//4. Load sbom data
CALL json_util.load_from_path("/anonymized_v4/sbom.spdx.json")
YIELD objects as obj
UNWIND obj AS data

// Create dependency nodes
UNWIND data.packages as package
MERGE (p:Package {
    name: package.name,
    version: package.versionInfo,
    spdx_id: package.SPDXID,
    download_location: package.downloadLocation,
    supplier: package.supplier,
    ecosystem: package.ecosystem
    })

WITH count(*) AS dummy

// 5. Load threat intelligence data
CALL json_util.load_from_path("/anonymized_v4/exploit_intelligence.json")
YIELD objects
UNWIND objects as obj

UNWIND obj.vulnerabilities as vuln
CREATE (t:ThreatSignal {
    cve: vuln.cve,
    epss: vuln.epss,
    kevListed: toBoolean(vuln.kevListed),
    publicExploit: toBoolean(vuln.publicExploit)
    })


// Create index for faster querying
CREATE INDEX ON :Vulnerability(name);
CREATE INDEX ON :Package(name);
CREATE INDEX ON :Asset(name);

// 6. Create relation between vulnerability and package

CALL json_util.load_from_path("/anonymized_v4/scanner_results.sarif.json")
YIELD objects AS obj
UNWIND obj AS data
UNWIND data.runs AS run
UNWIND run.results AS result
WITH result.ruleId AS ruleName, 
     result.level as resultLevel,
     result.message.text as desc,
     result.properties.package_name AS pname,
     result.properties.package_version AS pversion
MATCH (v:Vulnerability {name: ruleName})
MATCH (p:Package {name: pname, version: pversion})
MERGE (v)-[:EXISTS_IN]->(p)

WITH count(*) AS dummy

// 7. Create relation between assets and services
CALL json_util.load_from_path("/anonymized_v4/cmdb_assets.json")
YIELD objects as obj
UNWIND obj AS data
UNWIND data.assets as asset

MATCH (a:Asset {name: asset.assetId})
MATCH (s:Service {name: asset.service})

MERGE (a)-[:HOSTS]->(s)

WITH count(*) AS dummy

// 8. Create relation between asset and package
CALL json_util.load_from_path("/anonymized_v4/sbom.spdx.json")
YIELD objects as obj
UNWIND obj AS data
UNWIND data.relationships as relation
MATCH (a:Asset {name: substring(relation.spdxElementId, 6)})
MATCH (p:Package {spdx_id: relation.relatedSpdxElement})

MERGE (p)-[:INSTALLED_ON]->(a)

WITH count(*) AS dummy

// 9. Create relation between service and service
CALL json_util.load_from_path("/anonymized_v4/architecture.json")
YIELD objects as obj
UNWIND obj as data
UNWIND data.dependencies as dep
MATCH (src:Service {name: dep.source})
MATCH (tgt:Service {name: dep.target})

MERGE (src)-[:DEPENDS_ON]->(tgt)

WITH count(*) AS dummy

// 10. Creat threat intel relation
CALL json_util.load_from_path("/anonymized_v4/exploit_intelligence.json")
YIELD objects
UNWIND objects as obj
UNWIND obj.vulnerabilities as vuln
MATCH (v:Vulnerability {name: vuln.cve})
MATCH (t:ThreatSignal {cve: vuln.cve})
CREATE (v)-[:HAS]->(t)