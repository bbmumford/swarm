// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package swarm

// Topic naming conventions
//
// "fleet.*"          → HSTLES fleet fabric (shared across all partitions)
// "agent.*.<tenant>" → agent fabric, partition-scoped per multi-tenancy plan
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
// the given partition.
func AgentPolicyTopic(partitionID string) Topic { return Topic("agent.policy." + partitionID) }

// AgentTrustTopic returns the RD-epoch propagation topic scoped to the
// given partition.
func AgentTrustTopic(partitionID string) Topic { return Topic("agent.trust." + partitionID) }

// AgentKeysTopic carries KeyRotationEnvelope records.
func AgentKeysTopic(partitionID string) Topic { return Topic("agent.keys." + partitionID) }

// AgentBlocklistsTopic carries BlocklistManifest records.
func AgentBlocklistsTopic(partitionID string) Topic { return Topic("agent.blocklists." + partitionID) }

// AgentAssetsTopic carries AssetManifest records (admin-uploaded files).
func AgentAssetsTopic(partitionID string) Topic { return Topic("agent.assets." + partitionID) }

// AgentRulesTopic carries RuleManifest records for the given rule type
// ("yara" | "capa" | "sigma" | "flirt").
func AgentRulesTopic(partitionID, ruleType string) Topic {
	return Topic("agent.rules." + partitionID + "." + ruleType)
}

// AgentDriversTopic carries DriverManifest records for the given
// platform ("windows" | "macos" | "linux").
func AgentDriversTopic(partitionID, platform string) Topic {
	return Topic("agent.drivers." + partitionID + "." + platform)
}

// AgentVouchersTopic carries VoucherManifest records (offline enrollment).
func AgentVouchersTopic(partitionID string) Topic { return Topic("agent.vouchers." + partitionID) }

// AgentTUFMetaTopic carries TUFManifest records for the given release
// channel ("stable" | "beta" | "canary"). Not partition-scoped — the same
// binaries flow to every partition on the same channel.
func AgentTUFMetaTopic(channel string) Topic { return Topic("agent.tuf-meta." + channel) }

// AgentFIMBaselinesTopic carries FIMBaselineManifest records keyed by
// the SHA256 of the monitored path.
func AgentFIMBaselinesTopic(partitionID, pathHashHex string) Topic {
	return Topic("agent.fim-baselines." + partitionID + "." + pathHashHex)
}

// AgentOSQueryPacksTopic carries OSQueryPackManifest records.
func AgentOSQueryPacksTopic(partitionID string) Topic { return Topic("agent.osquery-packs." + partitionID) }

// AgentLiveQueryCacheTopic carries LiveQueryResultManifest records
// (opt-in cache of recent live-query results).
func AgentLiveQueryCacheTopic(partitionID string) Topic {
	return Topic("agent.livequery-cache." + partitionID)
}

// AgentForensicIndexTopic carries ForensicIndex records (artifact
// hashes only; raw bytes stay local for privacy).
func AgentForensicIndexTopic(partitionID string) Topic {
	return Topic("agent.forensic-index." + partitionID)
}

// AgentContentAdvertTopic is the per-partition content advert topic.
// Holders publish ContentAdvert records here; fetchers index them and
// route Fetch / FetchBlob calls to the named holders.
func AgentContentAdvertTopic(partitionID string) Topic {
	return Topic("agent.content.advert." + partitionID)
}

// ---------- Agent fabric topics: operational state ----------

// AgentDDNSTopic carries DDNSRecord records.
func AgentDDNSTopic(partitionID string) Topic { return Topic("agent.ddns." + partitionID) }

// AgentQuarantineTopic carries QuarantineNotice records.
func AgentQuarantineTopic(partitionID string) Topic { return Topic("agent.quarantine." + partitionID) }

// AgentDHCPTopic carries DHCPLeaseRecord records scoped to a segment.
func AgentDHCPTopic(partitionID, segment string) Topic {
	return Topic("agent.dhcp." + partitionID + "." + segment)
}

// AgentDiscoveredAssetsTopic carries DiscoveredAsset records.
func AgentDiscoveredAssetsTopic(partitionID string) Topic {
	return Topic("agent.discovered-assets." + partitionID)
}

// AgentPrintersTopic carries PrinterRecord records (deduplicated
// printer inventory).
func AgentPrintersTopic(partitionID string) Topic { return Topic("agent.printers." + partitionID) }

// AgentServiceStateTopic carries ServiceStateRecord records.
func AgentServiceStateTopic(partitionID string) Topic { return Topic("agent.service-state." + partitionID) }

// AgentInventoryDeltasTopic carries InventoryDelta records.
func AgentInventoryDeltasTopic(partitionID string) Topic {
	return Topic("agent.inventory-deltas." + partitionID)
}

// ---------- Agent fabric topics: security-critical ----------

// AgentRevokedKeysTopic carries RevocationNotice records.
func AgentRevokedKeysTopic(partitionID string) Topic { return Topic("agent.revoked-keys." + partitionID) }

// AgentNetworkPSKTopic carries NetworkPSKRotation records scoped to an
// epoch.
func AgentNetworkPSKTopic(partitionID string, epoch uint64) Topic {
	return Topic("agent.network-psk." + partitionID + "." + uint64ToDec(epoch))
}

// AgentTrustPinsTopic carries TrustPinUpdate records.
func AgentTrustPinsTopic(partitionID string) Topic { return Topic("agent.trust-pins." + partitionID) }

// AgentTLSPinsTopic carries TLSPinTOFU records per domain.
func AgentTLSPinsTopic(partitionID, domain string) Topic {
	return Topic("agent.tls-pins." + partitionID + "." + domain)
}

// AgentIntegrityAlertTopic carries IntegrityAlert records.
func AgentIntegrityAlertTopic(partitionID string) Topic {
	return Topic("agent.integrity-alert." + partitionID)
}

// ---------- Agent fabric topics: multi-session / multi-device ----------

// AgentSessionTopic carries SessionRecord records scoped to a device.
func AgentSessionTopic(partitionID, deviceID string) Topic {
	return Topic("agent.session." + partitionID + "." + deviceID)
}

// AgentConsentTopic carries ConsentRecord records keyed by user.
func AgentConsentTopic(partitionID, userID string) Topic {
	return Topic("agent.consent." + partitionID + "." + userID)
}

// AgentRemoteSessionsTopic carries RemoteSessionRecord records.
func AgentRemoteSessionsTopic(partitionID string) Topic {
	return Topic("agent.remote-sessions." + partitionID)
}

// AgentTunnelsTopic carries TunnelEndpoint records.
func AgentTunnelsTopic(partitionID string) Topic { return Topic("agent.tunnels." + partitionID) }

// ---------- Agent fabric topics: telemetry / observability ----------

// AgentHealthTopic carries HealthSummary records (the distinct gossip
// summary; the point-to-point "agent.mesh.Health" RPC is separate).
func AgentHealthTopic(partitionID string) Topic { return Topic("agent.health." + partitionID) }

// AgentEventTopic carries EventRecord records scoped to a type.
func AgentEventTopic(partitionID, eventType string) Topic {
	return Topic("agent.event." + partitionID + "." + eventType)
}

// AgentThreatSignalTopic carries ThreatSignal records.
func AgentThreatSignalTopic(partitionID string) Topic { return Topic("agent.threat-signal." + partitionID) }

// AgentDNSCacheTopic carries DNSCacheEntry records (privacy-aware
// opt-in).
func AgentDNSCacheTopic(partitionID string) Topic { return Topic("agent.dns-cache." + partitionID) }

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
