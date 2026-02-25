// Finding node: uniqueness and lookup indexes
CREATE CONSTRAINT finding_id IF NOT EXISTS
FOR (n:Finding) REQUIRE (n.tenant_id, n.id) IS UNIQUE;

CREATE INDEX finding_rule IF NOT EXISTS FOR (n:Finding) ON (n.tenant_id, n.rule_id);
CREATE INDEX finding_severity IF NOT EXISTS FOR (n:Finding) ON (n.tenant_id, n.severity);
CREATE INDEX finding_status IF NOT EXISTS FOR (n:Finding) ON (n.tenant_id, n.status);
CREATE INDEX finding_resource IF NOT EXISTS FOR (n:Finding) ON (n.tenant_id, n.resource_id);

// ConfigSnapshot node for baseline diffing
CREATE CONSTRAINT config_snapshot_id IF NOT EXISTS
FOR (n:ConfigSnapshot) REQUIRE (n.tenant_id, n.id) IS UNIQUE;

CREATE INDEX snapshot_resource IF NOT EXISTS FOR (n:ConfigSnapshot) ON (n.tenant_id, n.resource_id);
