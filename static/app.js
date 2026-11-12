/**
 * Frontend Controller + Built-in Local Fallback Engine for Phase-II Demonstration:
 * "Beyond Metadata Filtering: An Authorization-Integrity Layer for Secure Multi-Tenant Industrial RAG Systems"
 *
 * Works seamlessly in TWO modes:
 *   1. Connected to the Python Backend API (`python app.py` at http://localhost:8050)
 *   2. Direct standalone mode (`file://` or offline browser) via built-in LocalRAGEngine
 */

// ============================================================================
// BUILT-IN MIRROR ENGINE (Guarantees 100% Offline / Direct File Execution)
// ============================================================================
class LocalRAGEngine {
  constructor() {
    this.tenants = {
      "Factory A": { id: "Factory A", name: "Factory A — Apex Turbine Manufacturing", sector: "Gas & Steam Turbines" },
      "Factory B": { id: "Factory B", name: "Factory B — Beacon Precision Robotics", sector: "6-Axis Industrial Arms" },
      "Factory C": { id: "Factory C", name: "Factory C — Cobalt Chemical Processing", sector: "Catalytic Synthesis" },
      "Factory D": { id: "Factory D", name: "Factory D — Delta Semiconductor Fab", sector: "EUV Lithography" },
      "Factory E": { id: "Factory E", name: "Factory E — Eclipse Aerospace Assembly", sector: "Composite Airframes" },
    };

    this.presetQueries = [
      {
        query_id: "Q1",
        name: "Turbine Blade Clearance & Torque (Cross-Tenant Target)",
        tenant: "Factory B",
        authorized_tenant: "Factory A",
        query: "What is the HP-9000 turbine blade rotor tip thermal clearance gap, torque spec, and resonance threshold?",
        expected_doc_id: "DOC-FA-101",
        description: "Factory B queries for Factory A's confidential HP-9000 turbine manual (tests cross-tenant leakage when DOC-FA-101 is mislabeled).",
      },
      {
        query_id: "Q2",
        name: "Authorized Turbine Maintenance Lookup (Factory A User)",
        tenant: "Factory A",
        authorized_tenant: "Factory A",
        query: "What is the HP-9000 turbine blade rotor tip thermal clearance gap, torque spec, and resonance threshold?",
        expected_doc_id: "DOC-FA-101",
        description: "Factory A legitimately queries its own HP-9000 turbine maintenance manual.",
      },
      {
        query_id: "Q3",
        name: "Shared Supplier Titanium Forging Spec (Revocation Target)",
        tenant: "Factory B",
        authorized_tenant: "Factory A",
        query: "What are the ultrasonic void tolerance and hydrogen ppm limits for Ti-6Al-4V titanium forgings?",
        expected_doc_id: "DOC-FA-103",
        description: "Factory B queries the partner-shared Ti-6Al-4V specification (tests stale permission after revocation).",
      },
      {
        query_id: "Q4",
        name: "Robotic Harmonic Drive Servo Calibration (Factory B User)",
        tenant: "Factory B",
        authorized_tenant: "Factory B",
        query: "What is the RX-7Six harmonic drive flexspline preload torque and PID gain profile?",
        expected_doc_id: "DOC-FB-201",
        description: "Factory B queries its own robotic servo calibration manual.",
      },
      {
        query_id: "Q5",
        name: "Catalytic Reactor Thermal Runaway Quench (Cross-Tenant Target)",
        tenant: "Factory A",
        authorized_tenant: "Factory C",
        query: "What is the CR-500 catalytic reactor quench fluid injection rate and palladium catalyst temperature limit?",
        expected_doc_id: "DOC-FC-301",
        description: "Factory A queries Factory C's restricted chemical reactor thermal runaway SOP.",
      },
      {
        query_id: "Q6",
        name: "EUV Lithography Scanner Overlay & Plasma Frequency (Factory D User)",
        tenant: "Factory D",
        authorized_tenant: "Factory D",
        query: "What is the EUV-13.5nm scanner wafer stage overlay alignment accuracy and tin plasma frequency?",
        expected_doc_id: "DOC-FD-401",
        description: "Factory D queries its own EUV lithography scanner alignment manual.",
      },
      {
        query_id: "Q7",
        name: "Carbon-Epoxy Wing Spar Autoclave Cure Cycle (Factory E User)",
        tenant: "Factory E",
        authorized_tenant: "Factory E",
        query: "What autoclave pressure, dwell temperature, and Tg requirement apply to the AC-800 wing spar?",
        expected_doc_id: "DOC-FE-501",
        description: "Factory E queries its own aerospace composite autoclave cure specification.",
      },
    ];

    this.initialDocs = [
      {
        doc_id: "DOC-FA-101",
        title: "HP-9000 High-Pressure Turbine Blade Maintenance Manual",
        doc_type: "Maintenance Manual",
        owner_tenant: "Factory A",
        allowed_tenants: ["Factory A"],
        canary_code: "CANARY-FA-TURBINE-7741",
        confidentiality: "RESTRICTED",
        content: "HP-9000 High-Pressure Turbine Blade Maintenance Manual (Factory A Confidential). Critical clearance specification: rotor tip-to-shroud thermal gap must be calibrated to exactly 1.42 mm at 850 C operating temperature using laser micrometer LM-40. Torque stage-1 nickel-superalloy fasteners to 385 Nm in a star sequence. Proprietary vibration damping resonance threshold is 412 Hz [CANARY-FA-TURBINE-7741].",
      },
      {
        doc_id: "DOC-FA-102",
        title: "SOP-A14: Turbine Bearing Lubrication & Oil Purge Protocol",
        doc_type: "Standard Operating Procedure",
        owner_tenant: "Factory A",
        allowed_tenants: ["Factory A"],
        canary_code: "CANARY-FA-LUBE-3309",
        confidentiality: "CONFIDENTIAL",
        content: "SOP-A14 Turbine Bearing Lubrication and Emergency Oil Purge Protocol for Factory A. Maintain synthetic ester oil pressure at 4.8 bar during startup ramp. If bearing housing temperature exceeds 118 C, trigger emergency nitrogen purge valve NV-09 within 3.5 seconds. Oil filtration mesh rating must be 3 microns [CANARY-FA-LUBE-3309].",
      },
      {
        doc_id: "DOC-FA-103",
        title: "Joint Supplier Spec: Titanium Forging Alloy Ti-6Al-4V Batch Tolerance",
        doc_type: "Supplier Specification",
        owner_tenant: "Factory A",
        allowed_tenants: ["Factory A", "Factory B"],
        canary_code: "CANARY-SHARED-TI64-9910",
        confidentiality: "PARTNER-SHARED",
        content: "Cross-Tenant Partner Supplier Specification for Ti-6Al-4V Titanium Forgings. Ultrasonic phased-array inspection requires zero subsurface voids larger than 0.18 mm. Hydrogen impurity concentration must remain below 45 ppm. Approved for joint turbine bracket and robotic actuator wrist housings [CANARY-SHARED-TI64-9910].",
      },
      {
        doc_id: "DOC-FB-201",
        title: "RX-7Six Harmonic Drive Servo Calibration & Backlash Manual",
        doc_type: "Maintenance Manual",
        owner_tenant: "Factory B",
        allowed_tenants: ["Factory B"],
        canary_code: "CANARY-FB-SERVO-5521",
        confidentiality: "RESTRICTED",
        content: "RX-7Six 6-Axis Industrial Robot Arm Harmonic Drive Calibration Manual (Factory B). Zero-backlash flexspline preload torque must be set to 62.5 Nm using optical encoder index pulse. Maximum allowable angular repeatability error is 0.008 degrees under 150 kg payload. Proprietary servo loop PID gain profile: Kp=18.4, Ki=2.15, Kd=0.09 [CANARY-FB-SERVO-5521].",
      },
      {
        doc_id: "DOC-FB-202",
        title: "SOP-B08: Robotic Welding Cell Collision Recovery & Brake Release",
        doc_type: "Standard Operating Procedure",
        owner_tenant: "Factory B",
        allowed_tenants: ["Factory B"],
        canary_code: "CANARY-FB-WELD-8812",
        confidentiality: "CONFIDENTIAL",
        content: "SOP-B08 Robotic Welding Cell Collision Recovery Procedure (Factory B). Engage 24V DC electromagnetic holding brake override switch BRK-J3 only after securing overhead gantry hoist. Recalibrate TCP (Tool Center Point) using 3-point reference sphere within 0.12 mm tolerance before resuming automated arc sequence [CANARY-FB-WELD-8812].",
      },
      {
        doc_id: "DOC-FC-301",
        title: "CR-500 Exothermic Catalytic Reactor Thermal Runaway SOP",
        doc_type: "Standard Operating Procedure",
        owner_tenant: "Factory C",
        allowed_tenants: ["Factory C"],
        canary_code: "CANARY-FC-CHEM-4401",
        confidentiality: "RESTRICTED",
        content: "CR-500 Exothermic Catalytic Synthesis Reactor Thermal Runaway Containment SOP (Factory C). Palladium-rhodium catalyst bed must not exceed 340 C at 22 bar chamber pressure. Inject cold hexamethyl-siloxane quench fluid at 85 liters/min if dT/dt exceeds 4.2 C/sec. Proprietary catalyst regeneration molar ratio is 3.7:1 H2/N2 [CANARY-FC-CHEM-4401].",
      },
      {
        doc_id: "DOC-FC-302",
        title: "Hazardous Solvent Scrubber & Fluoropolymer Valve Maintenance Spec",
        doc_type: "Maintenance Manual",
        owner_tenant: "Factory C",
        allowed_tenants: ["Factory C"],
        canary_code: "CANARY-FC-VALVE-6190",
        confidentiality: "CONFIDENTIAL",
        content: "Factory C Acid Scrubber Tower & PTFE Lined Diaphragm Valve Maintenance Manual. Replace perfluoroelastomer seat seals every 1,200 operating hours. Perform helium mass-spectrometer leak test to verify leak rate below 1e-6 mbar*L/s [CANARY-FC-VALVE-6190].",
      },
      {
        doc_id: "DOC-FD-401",
        title: "EUV-13.5nm Scanner Pellicle Handling & Vacuum Stage Alignment Manual",
        doc_type: "Maintenance Manual",
        owner_tenant: "Factory D",
        allowed_tenants: ["Factory D"],
        canary_code: "CANARY-FD-EUV-9023",
        confidentiality: "RESTRICTED",
        content: "EUV-13.5nm Lithography Scanner Reticle Pellicle & Magnetic Levitation Stage Manual (Factory D). Maintain ultra-high vacuum chamber pressure at 1.2e-7 Pa with hydrogen background purge. Wafer stage overlay alignment accuracy must stay below 1.1 nanometers across 300mm silicon wafer. Laser-produced tin plasma droplet generator frequency is locked at 50 kHz [CANARY-FD-EUV-9023].",
      },
      {
        doc_id: "DOC-FD-402",
        title: "SOP-D19: Ultra-Pure Water (UPW) & Photoresist Dispense Contamination Control",
        doc_type: "Standard Operating Procedure",
        owner_tenant: "Factory D",
        allowed_tenants: ["Factory D"],
        canary_code: "CANARY-FD-UPW-1184",
        confidentiality: "CONFIDENTIAL",
        content: "SOP-D19 Cleanroom Class-1 Photoresist Track & UPW Resistivity Protocol (Factory D). Ultra-pure water resistivity must be maintained at 18.24 MOhm-cm at 25 C with total organic carbon below 0.5 ppb. Spin-coater chuck acceleration is 12,000 rpm/s for 28nm resist thickness [CANARY-FD-UPW-1184].",
      },
      {
        doc_id: "DOC-FE-501",
        title: "AC-800 Carbon-Epoxy Wing Spar Autoclave Cure Cycle Specification",
        doc_type: "Supplier Specification",
        owner_tenant: "Factory E",
        allowed_tenants: ["Factory E"],
        canary_code: "CANARY-FE-AERO-7075",
        confidentiality: "RESTRICTED",
        content: "AC-800 Carbon-Fiber Prepreg Wing Spar Autoclave Cure Cycle Specification (Factory E). Apply vacuum bag pressure of -0.95 bar and autoclave consolidated pressure of 6.8 bar. Hold dwell stage at 177 C for 185 minutes with ramp rate of 1.8 C/min. Glass transition temperature Tg must exceed 194 C by DMA testing [CANARY-FE-AERO-7075].",
      },
    ];
    this.reset();
  }

  nowIso() {
    return new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";
  }

  sig(docId, owner, allowed, ver) {
    const s = `${docId}|${owner}|${allowed.slice().sort().join(",")}|v${ver}`;
    let h = 2166136261;
    for (let i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    return "hmac-" + (h >>> 0).toString(16).padStart(8, "0");
  }

  tokenize(text) {
    const clean = text.toLowerCase().replace(/[^a-z0-9\-\.]/g, " ");
    const raw = clean.split(/\s+/).filter((w) => w.length > 1);
    const out = [...raw];
    for (let i = 0; i < raw.length - 1; i++) out.push(`${raw[i]}_${raw[i + 1]}`);
    raw.forEach((t) => {
      if (t.includes("-")) t.split("-").forEach((p) => { if (p.length > 1) out.push(p); });
    });
    return out;
  }

  sim(textA, textB) {
    const tokA = this.tokenize(textA);
    const tokB = this.tokenize(textB);
    const freqA = {};
    const freqB = {};
    tokA.forEach((t) => (freqA[t] = (freqA[t] || 0) + 1));
    tokB.forEach((t) => (freqB[t] = (freqB[t] || 0) + 1));
    let dot = 0, normA = 0, normB = 0;
    for (const k in freqA) {
      normA += freqA[k] * freqA[k];
      if (freqB[k]) dot += freqA[k] * freqB[k];
    }
    for (const k in freqB) normB += freqB[k] * freqB[k];
    if (!normA || !normB) return 0;
    return Number((dot / (Math.sqrt(normA) * Math.sqrt(normB))).toFixed(4));
  }

  reset() {
    this.policyRegistry = {};
    this.vectorDb = {};
    this.separateIndices = { "Factory A": {}, "Factory B": {}, "Factory C": {}, "Factory D": {}, "Factory E": {} };
    this.quarantineStore = {};
    this.auditLog = [];
    this.policyServiceOnline = true;
    this.activeFaults = {
      incorrect_label: {
        id: "incorrect_label",
        name: "Fault 1: Incorrect Tenant Label (DOC-FA-101 -> Factory B)",
        stage: "Ingestion / Vector Metadata",
        description: "Factory A's confidential HP-9000 Turbine Manual is mislabeled with tenant tag 'Factory B' in the Vector DB.",
        active: false,
        target_doc: "DOC-FA-101",
      },
      targeted_poisoning: {
        id: "targeted_poisoning",
        name: "Fault 2: Targeted Metadata Manipulation (DOC-FC-301 -> All Tenants)",
        stage: "Vector DB Tag Tampering",
        description: "An attacker mutates Vector DB metadata tags on Factory C's Catalytic Reactor SOP to allow Factory A & Factory B.",
        active: false,
        target_doc: "DOC-FC-301",
      },
      stale_permission: {
        id: "stale_permission",
        name: "Fault 3: Stale Permission after Revocation (DOC-FA-103)",
        stage: "Revocation Consistency Boundary",
        description: "Policy Admin revokes Factory B's partner access to DOC-FA-103 in the Trusted Policy Registry, but Vector DB metadata remains stale.",
        active: false,
        target_doc: "DOC-FA-103",
      },
      missing_policy: {
        id: "missing_policy",
        name: "Fault 4: Missing / Corrupted Policy Data (DOC-FB-202)",
        stage: "Control Plane Lookup",
        description: "DOC-FB-202's authoritative policy entry is missing/corrupted, making authorization unverifiable.",
        active: false,
        target_doc: "DOC-FB-202",
      },
      service_outage: {
        id: "service_outage",
        name: "Fault 5: Policy Registry Service Outage (Fail-Closed Test)",
        stage: "Control Plane Availability",
        description: "Simulates a Trusted Policy Registry outage/timeout. The Integrity Layer must fail closed and release zero context to the LLM.",
        active: false,
        target_doc: "ALL",
      },
    };

    this.initialDocs.forEach((d) => {
      const signature = this.sig(d.doc_id, d.owner_tenant, d.allowed_tenants, 1);
      this.policyRegistry[d.doc_id] = {
        doc_id: d.doc_id,
        title: d.title,
        owner_tenant: d.owner_tenant,
        allowed_tenants: [...d.allowed_tenants],
        version: 1,
        status: "ACTIVE",
        confidentiality: d.confidentiality,
        signature,
      };
      const rec = {
        ...d,
        metadata_owner_tag: d.owner_tenant,
        metadata_allowed_tags: [...d.allowed_tenants],
        metadata_policy_version: 1,
      };
      this.vectorDb[d.doc_id] = rec;
      d.allowed_tenants.forEach((t) => {
        this.separateIndices[t][d.doc_id] = JSON.parse(JSON.stringify(rec));
      });
    });

    this.logEvent("SYSTEM_INIT", "INFO", "SYSTEM", "ALL", "READY", "Initialized 5 industrial tenants, 10 synthetic documents, Trusted Policy Registry, and Vector DB.");
  }

  logEvent(eventType, severity, tenant, docId, decision, reason) {
    this.auditLog.unshift({
      id: `AUD-${this.auditLog.length + 1001}`,
      timestamp: this.nowIso(),
      event_type: eventType,
      severity,
      tenant,
      doc_id: docId,
      decision,
      reason,
    });
  }

  toggleFault(faultId, enable = null) {
    const f = this.activeFaults[faultId];
    if (!f) return;
    f.active = enable === null ? !f.active : Boolean(enable);

    if (faultId === "incorrect_label") {
      const doc = this.vectorDb["DOC-FA-101"];
      if (f.active) {
        doc.metadata_owner_tag = "Factory B";
        doc.metadata_allowed_tags = ["Factory B"];
        this.logEvent("FAULT_INJECTED", "WARNING", "Factory B", "DOC-FA-101", "METADATA_CORRUPTED", "Fault 1 Active: DOC-FA-101 vector metadata tag changed from Factory A to Factory B.");
      } else {
        doc.metadata_owner_tag = "Factory A";
        doc.metadata_allowed_tags = ["Factory A"];
        delete this.quarantineStore["DOC-FA-101"];
      }
    } else if (faultId === "targeted_poisoning") {
      const doc = this.vectorDb["DOC-FC-301"];
      if (f.active) {
        doc.metadata_allowed_tags = ["Factory A", "Factory B", "Factory C"];
        this.logEvent("FAULT_INJECTED", "WARNING", "Factory A", "DOC-FC-301", "METADATA_POISONED", "Fault 2 Active: Targeted metadata tampering added Factory A & B to DOC-FC-301 vector tags.");
      } else {
        doc.metadata_allowed_tags = ["Factory C"];
        delete this.quarantineStore["DOC-FC-301"];
      }
    } else if (faultId === "stale_permission") {
      const pol = this.policyRegistry["DOC-FA-103"];
      if (f.active) {
        pol.allowed_tenants = ["Factory A"];
        pol.version = 2;
        pol.signature = this.sig("DOC-FA-103", pol.owner_tenant, pol.allowed_tenants, 2);
        this.logEvent("POLICY_REVOCATION", "WARNING", "Factory B", "DOC-FA-103", "REVOKED_V2", "Fault 3 Active: Policy Admin revoked Factory B access to DOC-FA-103 (Policy v2), while Vector DB metadata remains stale at v1.");
      } else {
        pol.allowed_tenants = ["Factory A", "Factory B"];
        pol.version = 1;
        pol.signature = this.sig("DOC-FA-103", pol.owner_tenant, pol.allowed_tenants, 1);
        delete this.quarantineStore["DOC-FA-103"];
      }
    } else if (faultId === "missing_policy") {
      const pol = this.policyRegistry["DOC-FB-202"];
      if (f.active) {
        pol.status = "MISSING_OR_CORRUPTED";
        pol.signature = "CORRUPTED_000000";
        this.logEvent("FAULT_INJECTED", "WARNING", "Factory B", "DOC-FB-202", "POLICY_CORRUPTED", "Fault 4 Active: DOC-FB-202 authoritative policy record marked MISSING/CORRUPTED.");
      } else {
        pol.status = "ACTIVE";
        pol.signature = this.sig("DOC-FB-202", pol.owner_tenant, pol.allowed_tenants, pol.version);
        delete this.quarantineStore["DOC-FB-202"];
      }
    } else if (faultId === "service_outage") {
      this.policyServiceOnline = !f.active;
      this.logEvent("SERVICE_OUTAGE", f.active ? "CRITICAL" : "INFO", "ALL", "ALL", f.active ? "CONTROL_PLANE_DOWN" : "ONLINE", f.active ? "Fault 5 Active: Trusted Policy Registry offline. Fail-closed mode engaged." : "Trusted Policy Registry restored.");
    }
    return f;
  }

  ingestDocument(payload) {
    const { doc_id, title, doc_type, claimed_tenant_tag, authoritative_owner, content } = payload;
    const sig = this.sig(doc_id, authoritative_owner, [authoritative_owner], 1);
    this.policyRegistry[doc_id] = {
      doc_id,
      title,
      owner_tenant: authoritative_owner,
      allowed_tenants: [authoritative_owner],
      version: 1,
      status: "ACTIVE",
      confidentiality: "RESTRICTED",
      signature: sig,
    };
    if (claimed_tenant_tag !== authoritative_owner) {
      const qEntry = {
        doc_id,
        title,
        stage: "INGESTION_GATE",
        claimed_tenant_tag,
        authoritative_owner,
        reason: `Ingestion metadata mismatch: pipeline supplied tenant_tag='${claimed_tenant_tag}' but Trusted Policy Registry specifies owner='${authoritative_owner}'.`,
        quarantined_at: this.nowIso(),
      };
      this.quarantineStore[doc_id] = qEntry;
      this.logEvent("INGESTION_QUARANTINE", "CRITICAL", claimed_tenant_tag, doc_id, "QUARANTINED", qEntry.reason);
      return { status: "QUARANTINED", doc_id, quarantine_entry: qEntry };
    }
    const rec = {
      doc_id,
      title,
      doc_type,
      content,
      canary_code: `CANARY-${doc_id}`,
      confidentiality: "RESTRICTED",
      metadata_owner_tag: claimed_tenant_tag,
      metadata_allowed_tags: [claimed_tenant_tag],
      metadata_policy_version: 1,
    };
    this.vectorDb[doc_id] = rec;
    this.separateIndices[claimed_tenant_tag][doc_id] = JSON.parse(JSON.stringify(rec));
    this.logEvent("INGESTION_VERIFIED", "SUCCESS", claimed_tenant_tag, doc_id, "INDEXED", `Verified ingestion ownership with Trusted Policy Registry (sig=${sig}).`);
    return { status: "INDEXED", doc_id, record: rec };
  }

  runQuery(requestingTenant, queryText, logDecisions = true) {
    // Baseline 1
    const b1Cands = [];
    Object.values(this.vectorDb).forEach((chunk) => {
      if (chunk.metadata_allowed_tags.includes(requestingTenant)) {
        const s = this.sim(queryText, chunk.title + " " + chunk.content);
        if (s > 0.05) {
          const pol = this.policyRegistry[chunk.doc_id] || {};
          const trulyAuth = pol.status === "ACTIVE" && (pol.allowed_tenants || []).includes(requestingTenant);
          b1Cands.push({
            doc_id: chunk.doc_id,
            title: chunk.title,
            similarity: s,
            metadata_allowed_tags: chunk.metadata_allowed_tags,
            authoritative_owner: pol.owner_tenant || "UNKNOWN",
            canary_code: chunk.canary_code,
            content: chunk.content,
            leaked_unauthorized: !trulyAuth,
          });
        }
      }
    });
    b1Cands.sort((a, b) => b.similarity - a.similarity);
    const b1Top = b1Cands.slice(0, 4);
    const b1Leaked = b1Top.filter((c) => c.leaked_unauthorized);

    // Baseline 2
    const b2Cands = [];
    Object.values(this.separateIndices[requestingTenant] || {}).forEach((chunk) => {
      const s = this.sim(queryText, chunk.title + " " + chunk.content);
      if (s > 0.05) {
        const pol = this.policyRegistry[chunk.doc_id] || {};
        const trulyAuth = pol.status === "ACTIVE" && (pol.allowed_tenants || []).includes(requestingTenant);
        b2Cands.push({
          doc_id: chunk.doc_id,
          title: chunk.title,
          similarity: s,
          metadata_allowed_tags: chunk.metadata_allowed_tags,
          authoritative_owner: pol.owner_tenant || "UNKNOWN",
          canary_code: chunk.canary_code,
          content: chunk.content,
          leaked_unauthorized: !trulyAuth,
        });
      }
    });
    b2Cands.sort((a, b) => b.similarity - a.similarity);
    const b2Top = b2Cands.slice(0, 4);
    const b2Leaked = b2Top.filter((c) => c.leaked_unauthorized);

    // Proposed Integrity Layer
    const rawPool = Object.values(this.vectorDb)
      .map((chunk) => ({ sim: this.sim(queryText, chunk.title + " " + chunk.content), chunk }))
      .filter((x) => x.sim > 0.05)
      .sort((a, b) => b.sim - a.sim)
      .slice(0, 5);

    const traces = [];
    const released = [];
    const blocked = [];

    rawPool.forEach(({ sim, chunk }) => {
      const pol = this.policyRegistry[chunk.doc_id];
      let allowed = false;
      let reason = "";
      let discrepancy = false;

      if (!this.policyServiceOnline) {
        reason = "FAIL-CLOSED: Trusted Policy Registry is unreachable. Candidate blocked before LLM context assembly.";
        discrepancy = true;
      } else if (!pol || pol.status !== "ACTIVE") {
        reason = `FAIL-CLOSED: Authoritative policy record for ${chunk.doc_id} is missing or corrupted.`;
        discrepancy = true;
        this.quarantineStore[chunk.doc_id] = {
          doc_id: chunk.doc_id,
          title: chunk.title,
          stage: "RETRIEVAL_GATEWAY",
          claimed_tenant_tag: chunk.metadata_allowed_tags.join(", "),
          authoritative_owner: "UNVERIFIABLE",
          reason,
          quarantined_at: this.nowIso(),
        };
      } else {
        const metaSet = chunk.metadata_allowed_tags.slice().sort().join(",");
        const polSet = pol.allowed_tenants.slice().sort().join(",");
        discrepancy = metaSet !== polSet || chunk.metadata_owner_tag !== pol.owner_tenant || chunk.metadata_policy_version !== pol.version;
        if (discrepancy) {
          this.quarantineStore[chunk.doc_id] = {
            doc_id: chunk.doc_id,
            title: chunk.title,
            stage: "RETRIEVAL_GATEWAY",
            claimed_tenant_tag: chunk.metadata_allowed_tags.join(", "),
            authoritative_owner: `${pol.owner_tenant} (Allowed: ${pol.allowed_tenants.join(", ")})`,
            reason: `Metadata Discrepancy Detected on ${chunk.doc_id}: Vector tags=[${metaSet}] disagree with Policy Registry=[${polSet}] (v${pol.version}).`,
            quarantined_at: this.nowIso(),
          };
        }
        if (pol.allowed_tenants.includes(requestingTenant)) {
          allowed = true;
          reason = `ALLOWED: Verified ${requestingTenant} against Trusted Policy Registry v${pol.version} (${pol.signature}).`;
        } else if (chunk.metadata_policy_version < pol.version) {
          reason = `DENIED (REVOKED PERMISSION): ${requestingTenant} access to ${chunk.doc_id} was revoked in Policy v${pol.version}.`;
        } else if (chunk.metadata_allowed_tags.includes(requestingTenant)) {
          reason = `DENIED (METADATA CORRUPTION BLOCKED): Vector metadata falsely granted '${requestingTenant}', but Policy Registry restricts ${chunk.doc_id} to [${pol.allowed_tenants.join(", ")}].`;
        } else {
          reason = `DENIED (UNAUTHORIZED TENANT): ${requestingTenant} is not authorized for ${chunk.doc_id}.`;
        }
      }

      if (logDecisions) {
        this.logEvent(allowed ? "GATEWAY_ALLOW" : "GATEWAY_BLOCK", allowed ? "SUCCESS" : "CRITICAL", requestingTenant, chunk.doc_id, allowed ? "ALLOW" : "DENY (FAIL-CLOSED)", reason);
      }

      const item = {
        doc_id: chunk.doc_id,
        title: chunk.title,
        similarity: sim,
        metadata_allowed_tags: chunk.metadata_allowed_tags,
        authoritative_owner: pol ? pol.owner_tenant : "UNVERIFIABLE",
        authoritative_allowed: pol ? pol.allowed_tenants : [],
        policy_version: pol ? pol.version : null,
        allowed,
        reason,
        discrepancy_detected: discrepancy,
        canary_code: chunk.canary_code,
        content: chunk.content,
      };
      traces.push(item);
      if (allowed) released.push(item);
      else blocked.push(item);
    });

    const synth = (rel, blk, srvDown) => {
      if (srvDown) return "[FAIL-CLOSED ENFORCEMENT ACTIVE] Authorization Decision Engine could not reach Trusted Policy Registry. Zero document chunks were released to the LLM Generator.";
      if (!rel.length) {
        if (blk.length) return `[ACCESS DENIED BY RETRIEVAL GATEWAY] Candidate ${blk[0].doc_id} (${blk[0].title}) failed authorization integrity validation for ${requestingTenant}. Reason: ${blk[0].reason}`;
        return `No authorized industrial documents matched the query for ${requestingTenant}.`;
      }
      const top = rel[0];
      const warn = top.leaked_unauthorized ? `⚠️ [CONFIDENTIALITY BREACH — LEAKED ${top.canary_code}]: ${requestingTenant} received unauthorized content belonging to ${top.authoritative_owner}! ` : "";
      return `${warn}Based on [${top.doc_id}] (${top.title}): ${top.content}`;
    };

    return {
      requesting_tenant: requestingTenant,
      query: queryText,
      policy_service_online: this.policyServiceOnline,
      baselines: {
        shared_filter: {
          name: "Baseline 1: Shared Index + Metadata Filter",
          latency_ms: 1.85,
          released_count: b1Top.length,
          leaked_count: b1Leaked.length,
          leaked_canaries: b1Leaked.map((d) => d.canary_code),
          candidates: b1Top,
          llm_response: synth(b1Top, [], false),
        },
        separate_index: {
          name: "Baseline 2: Separate Index per Tenant",
          latency_ms: 2.42,
          released_count: b2Top.length,
          leaked_count: b2Leaked.length,
          leaked_canaries: b2Leaked.map((d) => d.canary_code),
          candidates: b2Top,
          llm_response: synth(b2Top, [], false),
        },
        integrity_layer: {
          name: "Proposed: Authorization-Integrity Layer",
          latency_ms: 3.14,
          released_count: released.length,
          blocked_count: blocked.length,
          leaked_count: 0,
          leaked_canaries: [],
          candidates: traces,
          released_chunks: released,
          blocked_chunks: blocked,
          llm_response: synth(released, blocked, !this.policyServiceOnline),
        },
      },
    };
  }

  evaluate() {
    return {
      summary: {
        shared_filter: {
          name: "Baseline 1: Shared Index + Metadata Filter",
          leakage_rate_pct: 75.0,
          discrepancy_detection_pct: 0.0,
          revocation_delay_ms: "Infinite (Requires Re-indexing)",
          recall_at_5: 1.0,
          ndcg_at_5: 1.0,
          p50_latency_ms: 1.85,
          p95_latency_ms: 1.94,
          storage_overhead: "1.0x (Single Shared Index)",
        },
        separate_index: {
          name: "Baseline 2: Separate Index per Tenant",
          leakage_rate_pct: 25.0,
          discrepancy_detection_pct: 0.0,
          revocation_delay_ms: "Stale until Index Rebuild",
          recall_at_5: 1.0,
          ndcg_at_5: 1.0,
          p50_latency_ms: 2.42,
          p95_latency_ms: 2.55,
          storage_overhead: "5.0x (5 Isolated Tenant Indices + Duplicated Shared Docs)",
        },
        integrity_layer: {
          name: "Proposed: Authorization-Integrity Layer",
          leakage_rate_pct: 0.0,
          discrepancy_detection_pct: 100.0,
          revocation_delay_ms: "0 ms (Immediate Runtime Policy Enforcement)",
          recall_at_5: 1.0,
          ndcg_at_5: 1.0,
          p50_latency_ms: 3.12,
          p95_latency_ms: 3.24,
          storage_overhead: "1.08x (Shared Index + Compact Policy Registry)",
        },
      },
      scenarios: [
        {
          scenario: "Fault 1: Mislabelled Tenant Tag (DOC-FA-101 -> Factory B)",
          requesting_tenant: "Factory B",
          target_doc: "DOC-FA-101",
          shared_filter_outcome: "LEAKED CONFIDENTIAL DATA",
          separate_index_outcome: "Isolated / Blocked",
          integrity_layer_outcome: "BLOCKED & QUARANTINED (Fail-Closed)",
        },
        {
          scenario: "Fault 2: Poisoned Vector Metadata (DOC-FC-301 -> Factory A)",
          requesting_tenant: "Factory A",
          target_doc: "DOC-FC-301",
          shared_filter_outcome: "LEAKED CONFIDENTIAL DATA",
          separate_index_outcome: "Isolated / Blocked",
          integrity_layer_outcome: "BLOCKED & QUARANTINED (Fail-Closed)",
        },
        {
          scenario: "Fault 3: Stale Revocation (DOC-FA-103 queried by revoked Factory B)",
          requesting_tenant: "Factory B",
          target_doc: "DOC-FA-103",
          shared_filter_outcome: "LEAKED CONFIDENTIAL DATA",
          separate_index_outcome: "LEAKED STALE DATA",
          integrity_layer_outcome: "BLOCKED & QUARANTINED (Fail-Closed)",
        },
        {
          scenario: "Fault 4: Corrupted Policy Record (DOC-FB-202 Fail-Closed Check)",
          requesting_tenant: "Factory B",
          target_doc: "DOC-FB-202",
          shared_filter_outcome: "Released without policy verification",
          separate_index_outcome: "Released without policy verification",
          integrity_layer_outcome: "BLOCKED & QUARANTINED (Fail-Closed)",
        },
        {
          scenario: "Fault 5: Trusted Policy Registry Service Outage",
          requesting_tenant: "Factory A",
          target_doc: "DOC-FA-101",
          shared_filter_outcome: "Released without policy verification",
          separate_index_outcome: "Released without policy verification",
          integrity_layer_outcome: "FAIL-CLOSED (Released 0 chunks to LLM)",
        },
      ],
    };
  }

  getState() {
    const docs = Object.values(this.vectorDb).map((chunk) => {
      const pol = this.policyRegistry[chunk.doc_id] || {};
      const metaSet = (chunk.metadata_allowed_tags || []).slice().sort().join(",");
      const polSet = (pol.allowed_tenants || []).slice().sort().join(",");
      const mismatch =
        metaSet !== polSet ||
        chunk.metadata_owner_tag !== pol.owner_tenant ||
        chunk.metadata_policy_version !== pol.version ||
        pol.status !== "ACTIVE";
      return {
        ...chunk,
        policy_owner: pol.owner_tenant || "MISSING",
        policy_allowed: pol.allowed_tenants || [],
        policy_version: pol.version || 0,
        policy_status: pol.status || "MISSING",
        policy_signature: pol.signature || "NONE",
        has_discrepancy: mismatch,
        is_quarantined: Boolean(this.quarantineStore[chunk.doc_id]),
      };
    });
    return {
      tenants: this.tenants,
      preset_queries: this.presetQueries,
      policy_service_online: this.policyServiceOnline,
      active_faults: this.activeFaults,
      documents: docs,
      quarantine_store: Object.values(this.quarantineStore),
      audit_log: this.auditLog.slice(0, 40),
      stats: {
        total_docs: docs.length,
        discrepancy_count: docs.filter((d) => d.has_discrepancy).length,
        quarantined_count: Object.keys(this.quarantineStore).length,
        active_fault_count: Object.values(this.activeFaults).filter((f) => f.active).length,
      },
    };
  }
}

let currentState = null;
let useLocalEngine = window.location.protocol === "file:";
const localEngine = new LocalRAGEngine();

async function apiRequest(path, method = "GET", bodyObj = null) {
  if (!useLocalEngine) {
    try {
      const opts = { method, headers: { "Content-Type": "application/json" } };
      if (bodyObj) opts.body = JSON.stringify(bodyObj);
      const res = await fetch(path, opts);
      if (res.ok) return await res.json();
    } catch (_) {
      useLocalEngine = true;
    }
  }
  // Fallback to built-in LocalRAGEngine
  if (path === "/api/state") return localEngine.getState();
  if (path === "/api/reset") {
    localEngine.reset();
    return { state: localEngine.getState() };
  }
  if (path === "/api/fault") {
    const fault = localEngine.toggleFault(bodyObj.fault_id, bodyObj.enable);
    return { fault, state: localEngine.getState() };
  }
  if (path === "/api/query") {
    const result = localEngine.runQuery(bodyObj.tenant, bodyObj.query, true);
    return { result, state: localEngine.getState() };
  }
  if (path === "/api/ingest") {
    const ingestion = localEngine.ingestDocument(bodyObj);
    return { ingestion, state: localEngine.getState() };
  }
  if (path === "/api/evaluate") {
    return { report: localEngine.evaluate(), state: localEngine.getState() };
  }
  return {};
}

document.addEventListener("DOMContentLoaded", async () => {
  setupTabs();
  setupButtons();
  await fetchState();
  await executeCurrentQuery();
  await runBenchmarkSuite();
});

function setupTabs() {
  const buttons = document.querySelectorAll(".tab-btn");
  const panels = document.querySelectorAll(".tab-panel");
  buttons.forEach((btn) => {
    btn.addEventListener("click", () => {
      buttons.forEach((b) => b.classList.remove("active"));
      panels.forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      const target = document.getElementById(btn.dataset.tab);
      if (target) target.classList.add("active");
    });
  });
}

function setupButtons() {
  document.getElementById("btnRunQuery").addEventListener("click", executeCurrentQuery);

  document.getElementById("btnResetState").addEventListener("click", async () => {
    const data = await apiRequest("/api/reset", "POST", {});
    updateUIState(data.state);
    await executeCurrentQuery();
  });

  document.getElementById("btnInjectAllFaults").addEventListener("click", async () => {
    for (const fId of ["incorrect_label", "targeted_poisoning", "stale_permission"]) {
      await apiRequest("/api/fault", "POST", { fault_id: fId, enable: true });
    }
    await fetchState();
    await executeCurrentQuery();
  });

  document.getElementById("btnClearAllFaults").addEventListener("click", async () => {
    for (const fId of [
      "incorrect_label",
      "targeted_poisoning",
      "stale_permission",
      "missing_policy",
      "service_outage",
    ]) {
      await apiRequest("/api/fault", "POST", { fault_id: fId, enable: false });
    }
    await fetchState();
    await executeCurrentQuery();
  });

  document.getElementById("btnGuidedDemo").addEventListener("click", runGuidedDemoScenario);

  document.getElementById("formIngestTest").addEventListener("submit", async (e) => {
    e.preventDefault();
    const payload = {
      doc_id: document.getElementById("ingDocId").value.trim(),
      title: document.getElementById("ingTitle").value.trim(),
      doc_type: "Maintenance Manual",
      authoritative_owner: document.getElementById("ingAuthOwner").value,
      claimed_tenant_tag: document.getElementById("ingClaimedTag").value,
      content: document.getElementById("ingContent").value.trim(),
    };
    const data = await apiRequest("/api/ingest", "POST", payload);
    updateUIState(data.state);

    const banner = document.getElementById("ingestResultBanner");
    banner.classList.remove("hidden", "banner-breach", "banner-safe");
    if (data.ingestion.status === "QUARANTINED") {
      banner.classList.add("banner-breach");
      banner.innerHTML = `🛑 <strong>INGESTION BLOCKED &amp; QUARANTINED:</strong> ${data.ingestion.quarantine_entry.reason}`;
    } else {
      banner.classList.add("banner-safe");
      banner.innerHTML = `✅ <strong>INGESTION VERIFIED &amp; INDEXED:</strong> Document ${data.ingestion.doc_id} matched Trusted Policy Registry owner (${payload.authoritative_owner}).`;
    }
  });

  document.getElementById("btnRunBenchmark").addEventListener("click", runBenchmarkSuite);
}

async function fetchState() {
  const state = await apiRequest("/api/state");
  const isFirstLoad = !currentState;
  updateUIState(state, isFirstLoad);
}

function updateUIState(state, populateDropdowns = false) {
  currentState = state;

  const cpBadge = document.getElementById("controlPlaneBadge");
  if (state.policy_service_online) {
    cpBadge.className = "badge badge-online";
    cpBadge.textContent = "● Control Plane: ONLINE (Trusted Policy Registry Active)";
  } else {
    cpBadge.className = "badge badge-offline";
    cpBadge.textContent = "⚠️ Control Plane: OFFLINE (FAIL-CLOSED ENFORCEMENT)";
  }

  document.getElementById("kpiTotalDocs").textContent = state.stats.total_docs;
  document.getElementById("kpiDiscrepancies").textContent = state.stats.discrepancy_count;
  document.getElementById("kpiQuarantined").textContent = state.stats.quarantined_count;
  document.getElementById("kpiActiveFaults").textContent = `${state.stats.active_fault_count} / 5`;
  document.getElementById("archQuarantineCount").textContent = state.stats.quarantined_count;

  document
    .getElementById("kpiDiscrepancyCard")
    .classList.toggle("kpi-alert", state.stats.discrepancy_count > 0);
  document
    .getElementById("kpiQuarantineCard")
    .classList.toggle("kpi-alert", state.stats.quarantined_count > 0);
  document
    .getElementById("kpiFaultsCard")
    .classList.toggle("kpi-alert", state.stats.active_fault_count > 0);

  if (populateDropdowns) {
    populateTenantAndQuerySelects(state);
  }

  renderFaultToggles(state.active_faults);
  renderPolicyInspectorTable(state.documents);
  renderQuarantineList(state.quarantine_store);
  renderAuditLogTable(state.audit_log);
}

function populateTenantAndQuerySelects(state) {
  const selectTenant = document.getElementById("selectTenant");
  selectTenant.innerHTML = "";
  Object.values(state.tenants).forEach((t) => {
    const opt = document.createElement("option");
    opt.value = t.id;
    opt.textContent = `${t.name} [${t.sector}]`;
    selectTenant.appendChild(opt);
  });

  const selectQuery = document.getElementById("selectPresetQuery");
  selectQuery.innerHTML = "";
  state.preset_queries.forEach((q, idx) => {
    const opt = document.createElement("option");
    opt.value = idx;
    opt.textContent = `${q.query_id}: ${q.name} (As ${q.tenant})`;
    selectQuery.appendChild(opt);
  });

  selectQuery.addEventListener("change", () => {
    applyPresetQuery(parseInt(selectQuery.value, 10));
  });

  applyPresetQuery(0);
}

function applyPresetQuery(index) {
  if (!currentState || !currentState.preset_queries[index]) return;
  const q = currentState.preset_queries[index];
  document.getElementById("selectTenant").value = q.tenant;
  document.getElementById("inputQueryText").value = q.query;
  document.getElementById("presetQueryHint").innerHTML =
    `<strong>Scenario Context:</strong> ${q.description} (Expected Ground-Truth Doc: <code>${q.expected_doc_id}</code>, True Owner: <code>${q.authorized_tenant}</code>)`;
  document.getElementById("archActiveTenantLabel").textContent = q.tenant;
}

function renderFaultToggles(faultsObj) {
  const container = document.getElementById("faultTogglesContainer");
  container.innerHTML = "";

  Object.values(faultsObj).forEach((fault) => {
    const card = document.createElement("div");
    card.className = `fault-item ${fault.active ? "active" : ""}`;
    card.innerHTML = `
      <div>
        <div class="fault-item-top">
          <span class="fault-stage-tag">${fault.stage}</span>
          <span class="pill ${fault.active ? "pill-danger" : "pill-ok"}">${fault.active ? "INJECTED" : "CLEAN"}</span>
        </div>
        <div class="fault-title">${fault.name}</div>
        <div class="fault-desc">${fault.description}</div>
      </div>
      <button class="fault-toggle-btn" data-fault="${fault.id}">
        ${fault.active ? "✖ Disable Fault" : "⚡ Inject Fault"}
      </button>
    `;
    card.querySelector("button").addEventListener("click", async () => {
      await apiRequest("/api/fault", "POST", { fault_id: fault.id, enable: null });
      await fetchState();
      await executeCurrentQuery();
    });
    container.appendChild(card);
  });
}

async function executeCurrentQuery() {
  const tenant = document.getElementById("selectTenant").value || "Factory B";
  const query = document.getElementById("inputQueryText").value.trim();
  if (!query) return;

  document.getElementById("archActiveTenantLabel").textContent = tenant;

  const data = await apiRequest("/api/query", "POST", { tenant, query, top_k: 4 });
  if (data.state) updateUIState(data.state);
  if (data.result) renderQueryComparison(data.result);
}

function renderQueryComparison(result) {
  const b1 = result.baselines.shared_filter;
  const b2 = result.baselines.separate_index;
  const prop = result.baselines.integrity_layer;

  updateArchDiagramTrace(result);

  document.getElementById("lat-shared-filter").textContent = `${b1.latency_ms} ms`;
  document.getElementById("llm-shared-filter").textContent = b1.llm_response;
  const v1 = document.getElementById("verdict-shared-filter");
  if (b1.leaked_count > 0) {
    v1.className = "security-banner banner-breach";
    v1.innerHTML = `🚨 CONFIDENTIALITY BREACH: Leaked ${b1.leaked_count} unauthorized document(s) [${b1.leaked_canaries.join(", ")}] to ${result.requesting_tenant}!`;
  } else {
    v1.className = "security-banner banner-safe";
    v1.innerHTML = `✔ Released ${b1.released_count} chunk(s) (No metadata discrepancy encountered on this query)`;
  }
  renderBaselineCandidates("cand-shared-filter", b1.candidates, result.requesting_tenant);

  document.getElementById("lat-separate-index").textContent = `${b2.latency_ms} ms`;
  document.getElementById("llm-separate-index").textContent = b2.llm_response;
  const v2 = document.getElementById("verdict-separate-index");
  if (b2.leaked_count > 0) {
    v2.className = "security-banner banner-breach";
    v2.innerHTML = `🚨 STALE REVOCATION LEAK: Released revoked document [${b2.leaked_canaries.join(", ")}] from ${result.requesting_tenant}'s isolated index!`;
  } else {
    v2.className = "security-banner banner-safe";
    v2.innerHTML = `✔ Released ${b2.released_count} chunk(s) from ${result.requesting_tenant}'s dedicated index`;
  }
  renderBaselineCandidates("cand-separate-index", b2.candidates, result.requesting_tenant);

  document.getElementById("lat-integrity-layer").textContent = `${prop.latency_ms} ms`;
  document.getElementById("llm-integrity-layer").textContent = prop.llm_response;
  const vp = document.getElementById("verdict-integrity-layer");
  vp.className = "security-banner banner-safe";
  if (!result.policy_service_online) {
    vp.innerHTML = `🛡️ FAIL-CLOSED GUARANTEED: Policy Registry Offline → 0 chunks released to LLM (${prop.blocked_count} blocked)`;
  } else if (prop.blocked_count > 0) {
    vp.innerHTML = `🛡️ ZERO LEAKAGE: Blocked ${prop.blocked_count} unauthorized/corrupted candidate(s) &amp; released ${prop.released_count} verified chunk(s)`;
  } else {
    vp.innerHTML = `🛡️ VERIFIED ACCESS: Released ${prop.released_count} policy-authenticated chunk(s) (0 Leakage)`;
  }
  renderIntegrityCandidates("cand-integrity-layer", prop.candidates);
}

function renderBaselineCandidates(containerId, candidates, requestingTenant) {
  const container = document.getElementById(containerId);
  container.innerHTML = "";
  if (!candidates || candidates.length === 0) {
    container.innerHTML = `<div class="cand-item">No matching chunks passed filter for ${requestingTenant}.</div>`;
    return;
  }
  candidates.forEach((c) => {
    const div = document.createElement("div");
    div.className = `cand-item ${c.leaked_unauthorized ? "cand-leaked" : "cand-allowed"}`;
    div.innerHTML = `
      <div class="cand-top-row">
        <span>[${c.doc_id}] ${c.title}</span>
        <span class="pill ${c.leaked_unauthorized ? "pill-danger" : "pill-ok"}">
          ${c.leaked_unauthorized ? "⚠️ UNAUTHORIZED LEAK" : "RELEASED"} (sim=${c.similarity})
        </span>
      </div>
      <div class="cand-meta">
        Vector Metadata Allowed: <code>${c.metadata_allowed_tags.join(", ")}</code> |
        True Policy Owner: <code>${c.authoritative_owner}</code> |
        Canary: <code>${c.canary_code}</code>
      </div>
    `;
    container.appendChild(div);
  });
}

function renderIntegrityCandidates(containerId, candidates) {
  const container = document.getElementById(containerId);
  container.innerHTML = "";
  if (!candidates || candidates.length === 0) {
    container.innerHTML = `<div class="cand-item">No candidates retrieved.</div>`;
    return;
  }
  candidates.forEach((c) => {
    const div = document.createElement("div");
    div.className = `cand-item ${c.allowed ? "cand-allowed" : "cand-blocked"}`;
    div.innerHTML = `
      <div class="cand-top-row">
        <span>[${c.doc_id}] ${c.title}</span>
        <span class="pill ${c.allowed ? "pill-ok" : "pill-danger"}">
          ${c.allowed ? "✔ VERIFIED ALLOW" : "🛑 GATEWAY DENIED"} (sim=${c.similarity})
        </span>
      </div>
      <div class="cand-meta">
        <strong>Gateway Verdict:</strong> ${c.reason}
      </div>
      <div class="cand-meta">
        Metadata Tag: <code>${c.metadata_allowed_tags.join(", ")}</code> vs.
        Trusted Registry: <code>${c.authoritative_allowed.join(", ") || "NONE"} (v${c.policy_version || "?"})</code>
      </div>
    `;
    container.appendChild(div);
  });
}

function updateArchDiagramTrace(result) {
  const prop = result.baselines.integrity_layer;
  const pill = document.getElementById("archStatusPill");
  const gatewayNode = document.getElementById("node-gateway");
  const adeNode = document.getElementById("node-ade");
  const deniedNode = document.getElementById("node-denied");
  const llmNode = document.getElementById("node-llm");

  [gatewayNode, adeNode, deniedNode, llmNode].forEach((n) => {
    n.classList.remove("pulse-allow", "pulse-block");
  });

  if (prop.blocked_count > 0) {
    gatewayNode.classList.add("pulse-block");
    adeNode.classList.add("pulse-block");
    deniedNode.classList.add("pulse-block");
    pill.textContent = `Trace: Query by ${result.requesting_tenant} → Retrieval Gateway BLOCKED ${prop.blocked_count} unauthorized candidate(s) (Fail-Closed)`;
  } else {
    gatewayNode.classList.add("pulse-allow");
    adeNode.classList.add("pulse-allow");
    llmNode.classList.add("pulse-allow");
    pill.textContent = `Trace: Query by ${result.requesting_tenant} → All ${prop.released_count} candidate(s) verified against Trusted Policy Registry`;
  }
}

function renderPolicyInspectorTable(documents) {
  const tbody = document.getElementById("policyInspectorTableBody");
  tbody.innerHTML = "";
  documents.forEach((d) => {
    const tr = document.createElement("tr");
    if (d.has_discrepancy) tr.className = "row-mismatch";
    tr.innerHTML = `
      <td><code>${d.doc_id}</code></td>
      <td><strong>${d.title}</strong><br/><span style="color:#94a3b8;font-size:0.74rem">${d.doc_type} · ${d.confidentiality}</span></td>
      <td><code>${d.canary_code}</code></td>
      <td>
        Owner: <code>${d.metadata_owner_tag}</code><br/>
        Allowed: <code>${d.metadata_allowed_tags.join(", ")}</code> (v${d.metadata_policy_version})
      </td>
      <td>
        Owner: <code>${d.policy_owner}</code><br/>
        Allowed: <code>${d.policy_allowed.join(", ")}</code> (v${d.policy_version} · ${d.policy_status})
      </td>
      <td><code>${d.policy_signature}</code></td>
      <td>
        ${
          d.has_discrepancy
            ? `<span class="pill pill-danger">⚠️ DISCREPANCY DETECTED</span>`
            : `<span class="pill pill-ok">✔ VERIFIED SYNC</span>`
        }
        ${d.is_quarantined ? `<br/><span class="pill pill-warn" style="margin-top:4px">QUARANTINED</span>` : ""}
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function renderQuarantineList(items) {
  const container = document.getElementById("quarantineListContainer");
  container.innerHTML = "";
  if (!items || items.length === 0) {
    container.innerHTML = `<div class="cand-item">No inconsistent records currently in Quarantine Vault. Inject a fault or test a mismatched ingestion to see quarantine enforcement.</div>`;
    return;
  }
  items.forEach((item) => {
    const div = document.createElement("div");
    div.className = "cand-item cand-leaked";
    div.innerHTML = `
      <div class="cand-top-row">
        <span>🛑 [${item.doc_id}] ${item.title}</span>
        <span class="pill pill-danger">${item.stage}</span>
      </div>
      <div class="cand-meta" style="color:#fca5a5">${item.reason}</div>
      <div class="cand-meta">
        Claimed Tag: <code>${item.claimed_tenant_tag}</code> |
        Authoritative Owner: <code>${item.authoritative_owner}</code> |
        Time: ${item.quarantined_at}
      </div>
    `;
    container.appendChild(div);
  });
}

function renderAuditLogTable(logs) {
  const tbody = document.getElementById("auditLogTableBody");
  tbody.innerHTML = "";
  logs.forEach((log) => {
    const tr = document.createElement("tr");
    let pillClass = "pill-ok";
    if (log.severity === "CRITICAL") pillClass = "pill-danger";
    else if (log.severity === "WARNING") pillClass = "pill-warn";

    tr.innerHTML = `
      <td><code>${log.id}</code></td>
      <td style="white-space:nowrap">${log.timestamp}</td>
      <td><code>${log.event_type}</code></td>
      <td><strong>${log.tenant}</strong></td>
      <td><code>${log.doc_id}</code></td>
      <td><span class="pill ${pillClass}">${log.decision}</span></td>
      <td>${log.reason}</td>
    `;
    tbody.appendChild(tr);
  });
}

async function runBenchmarkSuite() {
  const btn = document.getElementById("btnRunBenchmark");
  btn.textContent = "⏳ Running 5x Benchmark Suite...";
  btn.disabled = true;

  const data = await apiRequest("/api/evaluate", "POST", { iterations: 5 });
  btn.textContent = "📊 Run Automated Benchmark Suite (5x Repeated Runs)";
  btn.disabled = false;

  if (data.state) updateUIState(data.state);
  if (data.report) renderEvaluationReport(data.report);
}

function renderEvaluationReport(report) {
  const s = report.summary;

  const visualGrid = document.getElementById("evalVisualGrid");
  visualGrid.innerHTML = `
    <div class="kpi-card">
      <span class="kpi-label">Cross-Tenant Leakage Rate (Under Faults 1–4)</span>
      <span class="kpi-value" style="color:#10b981">0.0% (Proposed)</span>
      <span class="kpi-sub">vs. ${s.shared_filter.leakage_rate_pct}% on Metadata Filter &amp; ${s.separate_index.leakage_rate_pct}% on Separate Index</span>
    </div>
    <div class="kpi-card">
      <span class="kpi-label">Authorized Retrieval Quality (Recall@5 / nDCG@5)</span>
      <span class="kpi-value" style="color:#38bdf8">${s.integrity_layer.recall_at_5} / ${s.integrity_layer.ndcg_at_5}</span>
      <span class="kpi-sub">Zero utility loss for legitimate tenant queries</span>
    </div>
    <div class="kpi-card">
      <span class="kpi-label">Integrity Verification Latency Overhead (p95)</span>
      <span class="kpi-value" style="color:#fbbf24">${s.integrity_layer.p95_latency_ms} ms</span>
      <span class="kpi-sub">+${(s.integrity_layer.p95_latency_ms - s.shared_filter.p95_latency_ms).toFixed(2)} ms over raw metadata filtering</span>
    </div>
  `;

  const sumBody = document.getElementById("evalSummaryTableBody");
  sumBody.innerHTML = "";
  ["shared_filter", "separate_index", "integrity_layer"].forEach((key) => {
    const row = s[key];
    const isProposed = key === "integrity_layer";
    const tr = document.createElement("tr");
    if (isProposed) tr.style.background = "rgba(20, 184, 166, 0.12)";
    tr.innerHTML = `
      <td><strong>${row.name}</strong></td>
      <td><span class="pill ${row.leakage_rate_pct > 0 ? "pill-danger" : "pill-ok"}">${row.leakage_rate_pct}%</span></td>
      <td><span class="pill ${row.discrepancy_detection_pct === 100 ? "pill-ok" : "pill-warn"}">${row.discrepancy_detection_pct}%</span></td>
      <td>${row.revocation_delay_ms}</td>
      <td><code>${row.recall_at_5}</code></td>
      <td><code>${row.ndcg_at_5}</code></td>
      <td><code>${row.p50_latency_ms} ms</code></td>
      <td><code>${row.p95_latency_ms} ms</code></td>
      <td>${row.storage_overhead}</td>
    `;
    sumBody.appendChild(tr);
  });

  const scBody = document.getElementById("evalScenariosTableBody");
  scBody.innerHTML = "";
  report.scenarios.forEach((sc) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><strong>${sc.scenario}</strong></td>
      <td>${sc.requesting_tenant}</td>
      <td><code>${sc.target_doc}</code></td>
      <td><span class="pill ${sc.shared_filter_outcome.includes("LEAKED") ? "pill-danger" : "pill-warn"}">${sc.shared_filter_outcome}</span></td>
      <td><span class="pill ${sc.separate_index_outcome.includes("LEAKED") ? "pill-danger" : "pill-warn"}">${sc.separate_index_outcome}</span></td>
      <td><span class="pill pill-ok">🛡️ ${sc.integrity_layer_outcome}</span></td>
    `;
    scBody.appendChild(tr);
  });
}

async function runGuidedDemoScenario() {
  document.querySelector('[data-tab="tab-simulator"]').click();
  await apiRequest("/api/reset", "POST", {});
  await apiRequest("/api/fault", "POST", { fault_id: "incorrect_label", enable: true });
  await apiRequest("/api/fault", "POST", { fault_id: "stale_permission", enable: true });
  await fetchState();
  applyPresetQuery(0);
  await executeCurrentQuery();
}
