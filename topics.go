// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package swarm

// Topic naming conventions
//
// "fleet.*"          → HSTLES fleet fabric (shared across all tenants)
// "agent.*.<tenant>" → agent fabric, tenant-scoped per multi-tenancy plan
// "agent.*.<channel>" → agent fabric, channel-scoped (TUF stable|beta|canary)
//
// Each helper returns a swarm.Topic typed string. Subscribers register
// against the exact topic name; misspelled names silently produce zero
// delivery, so prefer these helpers over raw string concatenation.

// ---------- Fleet fabric topics ----------

// FleetPeerTopic is the unified PeerRecord topic for the HSTLES fleet mesh.
// PeerPublisher writes to this; RoleTable + AddressTable read from it.
const FleetPeerTopic Topic = "fleet.peer"

// FleetContentAdvertTopic carries ContentAdvert records for the fleet
// fabric. Matches the const used in content_impl.go.
const FleetContentAdvertTopic Topic = "fleet.content.advert"

// ---------- Agent fabric topics: distribution manifests ----------

// AgentPolicyTopic returns the policy-epoch propagation topic scoped to
// the given tenant.
func AgentPolicyTopic(tenantID string) Topic { return Topic("agent.policy." + tenantID) }

// AgentTrustTopic returns the RD-epoch propagation topic scoped to the
// given tenant.
func AgentTrustTopic(tenantID string) Topic { return Topic("agent.trust." + tenantID) }

// AgentKeysTopic carries KeyRotationEnvelope records.
func AgentKeysTopic(tenantID string) Topic { return Topic("agent.keys." + tenantID) }

// AgentBlocklistsTopic carries BlocklistManifest records.
func AgentBlocklistsTopic(tenantID string) Topic { return Topic("agent.blocklists." + tenantID) }

// AgentAssetsTopic carries AssetManifest records (admin-uploaded files).
func AgentAssetsTopic(tenantID string) Topic { return Topic("agent.assets." + tenantID) }

// AgentRulesTopic carries RuleManifest records for the given rule type
// ("yara" | "capa" | "sigma" | "flirt").
func AgentRulesTopic(tenantID, ruleType string) Topic {
	return Topic("agent.rules." + tenantID + "." + ruleType)
}

// AgentDriversTopic carries DriverManifest records for the given
// platform ("windows" | "macos" | "linux").
func AgentDriversTopic(tenantID, platform string) Topic {
	return Topic("agent.drivers." + tenantID + "." + platform)
}

// AgentVouchersTopic carries VoucherManifest records (offline enrollment).
func AgentVouchersTopic(tenantID string) Topic { return Topic("agent.vouchers." + tenantID) }

// AgentTUFMetaTopic carries TUFManifest records for the given release
// channel ("stable" | "beta" | "canary"). Not tenant-scoped — the same
// binaries flow to every tenant on the same channel.
func AgentTUFMetaTopic(channel string) Topic { return Topic("agent.tuf-meta." + channel) }

// AgentFIMBaselinesTopic carries FIMBaselineManifest records keyed by
// the SHA256 of the monitored path.
func AgentFIMBaselinesTopic(tenantID, pathHashHex string) Topic {
	return Topic("agent.fim-baselines." + tenantID + "." + pathHashHex)
}

// AgentOSQueryPacksTopic carries OSQueryPackManifest records.
func AgentOSQueryPacksTopic(tenantID string) Topic { return Topic("agent.osquery-packs." + tenantID) }

// AgentLiveQueryCacheTopic carries LiveQueryResultManifest records
// (opt-in cache of recent live-query results).
func AgentLiveQueryCacheTopic(tenantID string) Topic {
	return Topic("agent.livequery-cache." + tenantID)
}

// AgentForensicIndexTopic carries ForensicIndex records (artifact
// hashes only; raw bytes stay local for privacy).
func AgentForensicIndexTopic(tenantID string) Topic {
	return Topic("agent.forensic-index." + tenantID)
}

// AgentContentAdvertTopic is the per-tenant content advert topic.
// Holders publish ContentAdvert records here; fetchers index them and
// route Fetch / FetchBlob calls to the named holders.
func AgentContentAdvertTopic(tenantID string) Topic {
	return Topic("agent.content.advert." + tenantID)
}

// ---------- Agent fabric topics: operational state ----------

// AgentDDNSTopic carries DDNSRecord records.
func AgentDDNSTopic(tenantID string) Topic { return Topic("agent.ddns." + tenantID) }

// AgentQuarantineTopic carries QuarantineNotice records.
func AgentQuarantineTopic(tenantID string) Topic { return Topic("agent.quarantine." + tenantID) }

// AgentDHCPTopic carries DHCPLeaseRecord records scoped to a segment.
func AgentDHCPTopic(tenantID, segment string) Topic {
	return Topic("agent.dhcp." + tenantID + "." + segment)
}

// AgentDiscoveredAssetsTopic carries DiscoveredAsset records.
func AgentDiscoveredAssetsTopic(tenantID string) Topic {
	return Topic("agent.discovered-assets." + tenantID)
}

// AgentPrintersTopic carries PrinterRecord records (deduplicated
// printer inventory).
func AgentPrintersTopic(tenantID string) Topic { return Topic("agent.printers." + tenantID) }

// AgentServiceStateTopic carries ServiceStateRecord records.
func AgentServiceStateTopic(tenantID string) Topic { return Topic("agent.service-state." + tenantID) }

// AgentInventoryDeltasTopic carries InventoryDelta records.
func AgentInventoryDeltasTopic(tenantID string) Topic {
	return Topic("agent.inventory-deltas." + tenantID)
}

// ---------- Agent fabric topics: security-critical ----------

// AgentRevokedKeysTopic carries RevocationNotice records.
func AgentRevokedKeysTopic(tenantID string) Topic { return Topic("agent.revoked-keys." + tenantID) }

// AgentNetworkPSKTopic carries NetworkPSKRotation records scoped to an
// epoch.
func AgentNetworkPSKTopic(tenantID string, epoch uint64) Topic {
	return Topic("agent.network-psk." + tenantID + "." + uint64ToDec(epoch))
}

// AgentTrustPinsTopic carries TrustPinUpdate records.
func AgentTrustPinsTopic(tenantID string) Topic { return Topic("agent.trust-pins." + tenantID) }

// AgentTLSPinsTopic carries TLSPinTOFU records per domain.
func AgentTLSPinsTopic(tenantID, domain string) Topic {
	return Topic("agent.tls-pins." + tenantID + "." + domain)
}

// AgentIntegrityAlertTopic carries IntegrityAlert records.
func AgentIntegrityAlertTopic(tenantID string) Topic {
	return Topic("agent.integrity-alert." + tenantID)
}

// ---------- Agent fabric topics: multi-session / multi-device ----------

// AgentSessionTopic carries SessionRecord records scoped to a device.
func AgentSessionTopic(tenantID, deviceID string) Topic {
	return Topic("agent.session." + tenantID + "." + deviceID)
}

// AgentConsentTopic carries ConsentRecord records keyed by user.
func AgentConsentTopic(tenantID, userID string) Topic {
	return Topic("agent.consent." + tenantID + "." + userID)
}

// AgentRemoteSessionsTopic carries RemoteSessionRecord records.
func AgentRemoteSessionsTopic(tenantID string) Topic {
	return Topic("agent.remote-sessions." + tenantID)
}

// AgentTunnelsTopic carries TunnelEndpoint records.
func AgentTunnelsTopic(tenantID string) Topic { return Topic("agent.tunnels." + tenantID) }

// ---------- Agent fabric topics: telemetry / observability ----------

// AgentHealthTopic carries HealthSummary records (the distinct gossip
// summary; the point-to-point "agent.mesh.Health" RPC is separate).
func AgentHealthTopic(tenantID string) Topic { return Topic("agent.health." + tenantID) }

// AgentEventTopic carries EventRecord records scoped to a type.
func AgentEventTopic(tenantID, eventType string) Topic {
	return Topic("agent.event." + tenantID + "." + eventType)
}

// AgentThreatSignalTopic carries ThreatSignal records.
func AgentThreatSignalTopic(tenantID string) Topic { return Topic("agent.threat-signal." + tenantID) }

// AgentDNSCacheTopic carries DNSCacheEntry records (privacy-aware
// opt-in).
func AgentDNSCacheTopic(tenantID string) Topic { return Topic("agent.dns-cache." + tenantID) }

// ---------- Edge service roles ----------
//
// Edge service roles advertise specialised duties on top of the base
// Role enum (anchor / relay / member). A peer can hold any combination
// of these; advertisement is via PeerRecord.Capabilities.edge_roles.
// Consumers use these constants instead of raw strings so a typo is
// caught at compile time.

const (
	// EdgeRoleTelemetryAggregator collects + forwards telemetry from
	// nearby device peers to the central pipeline.
	EdgeRoleTelemetryAggregator = "telemetry-aggregator"

	// EdgeRoleOTelExporter exports OpenTelemetry spans/metrics on
	// behalf of peers that lack direct egress to the collector.
	EdgeRoleOTelExporter = "otel-exporter"

	// EdgeRoleC2Cache caches recent C2 bundle responses and serves
	// peers that prefer mesh-local fetches over WAN round-trips.
	EdgeRoleC2Cache = "c2-cache"

	// EdgeRoleSignalingRelay relays hole-punch / NAT signaling between
	// peers that cannot establish direct paths.
	EdgeRoleSignalingRelay = "signaling-relay"

	// EdgeRoleSNMPDiscoverer runs subnet-scoped SNMP discovery and
	// publishes DiscoveredAsset / PrinterRecord topics.
	EdgeRoleSNMPDiscoverer = "snmp-discoverer"

	// EdgeRoleTUFCache pre-warms TUF metadata + binaries for the local
	// segment so first-launch updates don't burn WAN.
	EdgeRoleTUFCache = "tuf-cache"

	// EdgeRoleDDNSPublisher publishes DDNSRecord entries for the local
	// segment's mesh-internal Hidden + Admin zones.
	EdgeRoleDDNSPublisher = "ddns-publisher"

	// EdgeRoleDHCPBridge bridges DHCP leases between the local network
	// and the mesh fabric (publishes DHCPLeaseRecord).
	EdgeRoleDHCPBridge = "dhcp-bridge"

	// EdgeRolePrintRelay accepts mesh print jobs and submits them to
	// physical printers on the local segment.
	EdgeRolePrintRelay = "print-relay"

	// EdgeRoleBlocklistPublisher fetches upstream blocklists and
	// republishes them as BlocklistManifest records.
	EdgeRoleBlocklistPublisher = "blocklist-publisher"

	// EdgeRoleAssetPublisher distributes admin-uploaded assets via
	// AssetManifest records.
	EdgeRoleAssetPublisher = "asset-publisher"
)

// AllEdgeRoles is the canonical set. Useful for validation + UI
// enumeration.
func AllEdgeRoles() []string {
	return []string{
		EdgeRoleTelemetryAggregator,
		EdgeRoleOTelExporter,
		EdgeRoleC2Cache,
		EdgeRoleSignalingRelay,
		EdgeRoleSNMPDiscoverer,
		EdgeRoleTUFCache,
		EdgeRoleDDNSPublisher,
		EdgeRoleDHCPBridge,
		EdgeRolePrintRelay,
		EdgeRoleBlocklistPublisher,
		EdgeRoleAssetPublisher,
	}
}

// uint64ToDec returns the base-10 decimal representation of v without
// importing strconv (keeps the topics package zero-dep).
func uint64ToDec(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
