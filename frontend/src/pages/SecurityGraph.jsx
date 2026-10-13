import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Bot,
  CheckCircle2,
  CircleDot,
  Cloud,
  Database,
  ExternalLink,
  Eye,
  GitBranch,
  Info,
  KeyRound,
  Layers3,
  Maximize2,
  Minus,
  Network,
  Plus,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Target,
  User,
  Users,
  X,
  Zap,
} from "lucide-react";

import api from "../services/api";

import "./SecurityGraph.css";


// ============================================================
// CONSTANTS
// ============================================================

const GRAPH_API = "/security-graph";

const MAX_VISIBLE_NODES = 120;

const NODE_WIDTH = 190;
const NODE_HEIGHT = 58;

const RELATIONSHIP_COLORS = {
  EXPOSES: "#fb7185",
  ASSUMES_ROLE: "#a78bfa",
  GRANTS: "#fbbf24",
  TRUSTS: "#2dd4bf",
  CONNECTED_TO: "#38bdf8",
  CONTAINS: "#93c5fd",
  ASSOCIATED_WITH: "#94a3b8",
};

const NODE_ICONS = {
  INTERNET: Cloud,
  PUBLIC_INTERNET: Cloud,

  AWS_ACCOUNT: Shield,

  EC2: Server,
  EC2_INSTANCE: Server,

  SECURITY_GROUP: ShieldCheck,
  EC2_SECURITY_GROUP: ShieldCheck,

  IAM_ROLE: KeyRound,
  IAM_POLICY: KeyRound,
  IAM_USER: User,
  IAM_USER_POLICY: KeyRound,

  LAMBDA: Zap,
  LAMBDA_FUNCTION: Zap,

  RDS: Database,
  RDS_DATABASE: Database,

  VPC: Network,
  SUBNET: Network,

  INTERNET_GATEWAY: Cloud,
  ROUTE_TABLE: Network,

  FINDING: AlertTriangle,

  RESOURCE: Layers3,
};


// ============================================================
// HELPERS
// ============================================================

function text(value, fallback = "") {
  if (
    value === null ||
    value === undefined
  ) {
    return fallback;
  }

  return String(value);
}


function upper(value, fallback = "") {
  return text(value, fallback)
    .trim()
    .toUpperCase();
}


function number(value, fallback = 0) {
  const parsed = Number(value);

  return Number.isFinite(parsed)
    ? parsed
    : fallback;
}


function getArray(value) {
  return Array.isArray(value)
    ? value
    : [];
}


function getNodeType(node) {
  return upper(
    node?.node_type ||
      node?.type ||
      node?.resource_type ||
      "RESOURCE"
  ).replaceAll(" ", "_");
}


function getNodeId(node) {
  return text(
    node?.node_id ||
      node?.id ||
      node?.resource_id ||
      node?._id
  );
}


function getNodeName(node) {
  return text(
    node?.resource_name ||
      node?.name ||
      node?.resource_id ||
      node?.node_id ||
      "Unknown resource"
  );
}


function getNodeService(node) {
  return upper(
    node?.service ||
      node?.aws_service ||
      ""
  );
}


function getEdgeType(edge) {
  return upper(
    edge?.relationship_type ||
      edge?.type ||
      edge?.relation ||
      "ASSOCIATED_WITH"
  ).replaceAll(" ", "_");
}


function getEdgeSource(edge) {
  return text(
    edge?.source ||
      edge?.source_id ||
      edge?.from
  );
}


function getEdgeTarget(edge) {
  return text(
    edge?.target ||
      edge?.target_id ||
      edge?.to
  );
}


function getEvidence(edge) {
  const evidence =
    edge?.evidence;

  if (
    evidence &&
    typeof evidence === "object"
  ) {
    return evidence;
  }

  return {};
}


function isVerifiedEdge(edge) {
  const evidence = getEvidence(edge);

  return (
    evidence?.verified === true ||
    edge?.verified === true
  );
}


function isFindingNode(node) {
  return (
    getNodeType(node) === "FINDING"
  );
}


function getSeverity(node) {
  return upper(
    node?.severity ||
      node?.signals?.severity ||
      ""
  );
}


function getSeverityClass(severity) {
  switch (upper(severity)) {
    case "CRITICAL":
      return "critical";

    case "HIGH":
      return "high";

    case "MEDIUM":
      return "medium";

    case "LOW":
      return "low";

    default:
      return "info";
  }
}


function getNodeIcon(type) {
  return (
    NODE_ICONS[type] ||
    Layers3
  );
}


function getRelationshipColor(type) {
  return (
    RELATIONSHIP_COLORS[type] ||
    "#64748b"
  );
}


function formatDate(value) {
  if (!value) {
    return "Unknown";
  }

  const date = new Date(value);

  if (
    Number.isNaN(
      date.getTime()
    )
  ) {
    return text(value);
  }

  return date.toLocaleString();
}


function compact(value) {
  const valueText = text(value);

  if (valueText.length <= 24) {
    return valueText;
  }

  return `${valueText.slice(0, 11)}…${valueText.slice(-9)}`;
}


function extractAccountId(...sources) {
  // CloudGuardAI internal account IDs are Mongo/ObjectId values.
  // A 12-digit numeric value is the real AWS account ID and must NOT
  // be sent to get_account(), which expects the internal account ID.
  const isAwsAccountId = (value) => /^\d{12}$/.test(text(value));

  for (const source of sources) {
    if (!source || typeof source !== "object") {
      continue;
    }

    const preferred =
      source.cloudguard_account_id ||
      source.cloudguardAccountId ||
      source.account?.id ||
      source.account?._id;

    if (preferred && !isAwsAccountId(preferred)) {
      return text(preferred);
    }
  }

  // Fall back to the direct account identifier even when it is the
  // real 12-digit AWS account ID. The security-correlation backend
  // intentionally accepts both identifiers and resolves AWS IDs through
  // the authenticated tenant boundary. This is important for graph nodes,
  // because scan-level topology stores the AWS account number on each node.
  for (const source of sources) {
    if (!source || typeof source !== "object") {
      continue;
    }

    const direct = source.account_id || source.accountId;

    if (direct) {
      return text(direct);
    }
  }

  return "";
}


// ============================================================
// GRAPH LAYOUT
// ============================================================

function buildGraphLayout(
  nodes,
  edges
) {
  const safeNodes =
    nodes.slice(
      0,
      MAX_VISIBLE_NODES
    );

  const nodeMap =
    new Map(
      safeNodes.map(
        (node) => [
          getNodeId(node),
          node,
        ]
      )
    );

  const safeEdges =
    edges.filter(
      (edge) =>
        nodeMap.has(
          getEdgeSource(edge)
        ) &&
        nodeMap.has(
          getEdgeTarget(edge)
        )
    );

  const adjacency =
    new Map();

  safeNodes.forEach(
    (node) => {
      adjacency.set(
        getNodeId(node),
        []
      );
    }
  );

  safeEdges.forEach(
    (edge) => {
      const source =
        getEdgeSource(edge);

      const target =
        getEdgeTarget(edge);

      if (
        adjacency.has(source)
      ) {
        adjacency
          .get(source)
          .push(target);
      }

      if (
        adjacency.has(target)
      ) {
        adjacency
          .get(target)
          .push(source);
      }
    }
  );

  // ----------------------------------------------------------
  // Assign rough security-topology layers.
  // ----------------------------------------------------------

  const layerForNode =
    (node) => {
      const type =
        getNodeType(node);

      if (
        type === "INTERNET" ||
        type === "PUBLIC_INTERNET"
      ) {
        return 0;
      }

      if (
        type === "AWS_ACCOUNT"
      ) {
        return 0;
      }

      if (
        [
          "VPC",
          "SUBNET",
          "INTERNET_GATEWAY",
          "ROUTE_TABLE",
        ].includes(type)
      ) {
        return 1;
      }

      if (
        [
          "SECURITY_GROUP",
          "EC2_SECURITY_GROUP",
        ].includes(type)
      ) {
        return 2;
      }

      if (
        [
          "EC2",
          "EC2_INSTANCE",
          "LAMBDA",
          "LAMBDA_FUNCTION",
          "RDS",
          "RDS_DATABASE",
        ].includes(type)
      ) {
        return 3;
      }

      if (
        [
          "IAM_ROLE",
          "IAM_POLICY",
          "IAM_USER",
          "IAM_USER_POLICY",
        ].includes(type)
      ) {
        return 4;
      }

      if (
        type === "FINDING"
      ) {
        return 5;
      }

      return 3;
    };

  const layers = [];

  safeNodes.forEach(
    (node) => {
      const layer =
        layerForNode(node);

      if (!layers[layer]) {
        layers[layer] = [];
      }

      layers[layer].push(node);
    }
  );

  const positions =
    new Map();

  const horizontalGap = 225;
  const verticalGap = 92;

  layers.forEach(
    (layerNodes, layerIndex) => {
      if (!layerNodes) {
        return;
      }

      const totalWidth =
        layerNodes.length *
        horizontalGap;

      const startX =
        Math.max(
          100,
          600 -
            totalWidth / 2
        );

      layerNodes.forEach(
        (node, index) => {
          const nodeId =
            getNodeId(node);

          const y =
            80 +
            index *
              verticalGap;

          positions.set(
            nodeId,
            {
              x:
                startX +
                index *
                  horizontalGap,
              y:
                layerIndex *
                  145 +
                y,
            }
          );
        }
      );
    }
  );

  return {
    nodes: safeNodes,
    edges: safeEdges,
    positions,
    width: 1450,
    height: Math.max(
      800,
      ...layers.map(
        (layer) =>
          layer
            ? layer.length *
                verticalGap +
              150
            : 0
      )
    ),
  };
}


// ============================================================
// COMPONENT
// ============================================================

function SecurityGraph() {
  // ----------------------------------------------------------
  // DATA
  // ----------------------------------------------------------

  const [graph, setGraph] =
    useState(null);

  const [summary, setSummary] =
    useState(null);

  const [attackPaths, setAttackPaths] =
    useState([]);

  const [analysis, setAnalysis] =
    useState(null);

  const [accountId, setAccountId] =
    useState("");

  const [correlation, setCorrelation] =
    useState(null);

  const [correlationLoading, setCorrelationLoading] =
    useState(false);

  const [correlationError, setCorrelationError] =
    useState("");

  const correlationRequestRef =
    useRef(0);

  // ----------------------------------------------------------
  // UI
  // ----------------------------------------------------------

  const [loading, setLoading] =
    useState(true);

  const [refreshing, setRefreshing] =
    useState(false);

  const [error, setError] =
    useState("");

  const [activeTab, setActiveTab] =
    useState("overview");

  const [serviceFilter, setServiceFilter] =
    useState("ALL");

  const [showFindings, setShowFindings] =
    useState(true);

  const [verifiedOnly, setVerifiedOnly] =
    useState(true);

  const [selectedNode, setSelectedNode] =
    useState(null);

  const [selectedEdge, setSelectedEdge] =
    useState(null);

  const [zoom, setZoom] =
    useState(0.6);

  const [pan, setPan] =
    useState({
      x: 0,
      y: 0,
    });

  // ----------------------------------------------------------
  // LOAD GRAPH
  // ----------------------------------------------------------

  const loadGraph =
    useCallback(
      async (
        silent = false
      ) => {
        if (!silent) {
          setLoading(true);
        }

        setRefreshing(true);
        setError("");

        try {
          const [
            graphResponse,
            attackResponse,
            summaryResponse,
          ] =
            await Promise.all([
              api.get(
                `${GRAPH_API}/`
              ),

              api.get(
                `${GRAPH_API}/attack-paths`
              ),

              api.get(
                `${GRAPH_API}/summary`
              ),
            ]);

          const graphData =
            graphResponse?.data?.graph ||
            graphResponse?.data ||
            {};

          const attackData =
            attackResponse?.data ||
            {};

          const summaryData =
            summaryResponse?.data ||
            {};

          // --------------------------------------------------
          // GRAPH
          // --------------------------------------------------

          setGraph(
            graphData
          );

          // --------------------------------------------------
          // SUMMARY
          //
          // IMPORTANT:
          // Backend summary is authoritative for security
          // indicators.
          // --------------------------------------------------

          setSummary(
            summaryData?.summary ||
              {}
          );

          // --------------------------------------------------
          // ATTACK PATHS
          // --------------------------------------------------

          setAttackPaths(
            Array.isArray(
              attackData?.attack_paths
            )
              ? attackData.attack_paths
              : []
          );

          // --------------------------------------------------
          // ANALYSIS
          // --------------------------------------------------

          setAnalysis(
            graphData?.analysis ||
              summaryData?.analysis ||
              null
          );

          // Resolve the CloudGuardAI account identity used by the
          // correlation API. Never guess across tenants/accounts.
          let resolvedAccountId = extractAccountId(
            graphData,
            summaryData,
            graphData?.account,
            summaryData?.account,
            graphData?.metadata,
            summaryData?.metadata
          );

          // The persisted graph uses account_id for the REAL AWS account
          // number. Correlation needs CloudGuardAI's internal account ID.
          // Resolve it through the tenant-scoped /aws/accounts endpoint.
          const resolvedLooksLikeAwsId = /^\d{12}$/.test(
            text(resolvedAccountId)
          );

          // If the graph only exposes the real AWS account number, it is
          // still a valid correlation identifier. The backend resolves it
          // tenant-safely via get_account_by_aws_id(). Only perform the
          // account-list lookup when no usable identifier is available.
          if (!resolvedAccountId) {
            try {
              const accountsResponse =
                await api.get("/aws/accounts");

              const accounts =
                Array.isArray(accountsResponse?.data)
                  ? accountsResponse.data
                  : Array.isArray(accountsResponse?.data?.accounts)
                    ? accountsResponse.data.accounts
                    : [];

              const graphAwsAccountId = text(
                graphData?.aws_account_id ||
                  graphData?.awsAccountId ||
                  summaryData?.aws_account_id ||
                  summaryData?.awsAccountId
              );

              const matchingAccount =
                graphAwsAccountId
                  ? accounts.find((account) => {
                      const awsId = text(
                        account?.aws_account_id ||
                          account?.awsAccountId ||
                          account?.aws_id
                      );

                      return (
                        awsId &&
                        graphAwsAccountId === awsId
                      );
                    })
                  : null;

              resolvedAccountId = text(
                matchingAccount?._id ||
                  matchingAccount?.id ||
                  matchingAccount?.account_id
              );
            } catch (accountError) {
              console.warn(
                "Unable to resolve AWS account for security correlation:",
                accountError
              );
            }
          }

          setAccountId(resolvedAccountId);
          setCorrelation(null);
          setCorrelationError("");
        } catch (err) {
          console.error(
            "Security graph loading error:",
            err
          );

          const status =
            err?.response?.status;

          if (status === 401) {
            setError(
              "Your session has expired. Please sign in again."
            );
          } else if (
            status === 403
          ) {
            setError(
              "You do not have permission to view this security graph."
            );
          } else {
            setError(
              err?.response?.data
                ?.detail ||
                "Unable to load the security graph."
            );
          }
        } finally {
          setLoading(false);
          setRefreshing(false);
        }
      },
      []
    );

  // ----------------------------------------------------------
  // INITIAL LOAD
  // ----------------------------------------------------------

  useEffect(() => {
    loadGraph();
  }, [loadGraph]);

  // ============================================================
  // NORMALIZED GRAPH DATA
  // ============================================================

  const rawNodes =
    useMemo(
      () =>
        getArray(
          graph?.nodes
        ),
      [graph]
    );

  const rawEdges =
    useMemo(
      () =>
        getArray(
          graph?.relationships ||
            graph?.edges
        ),
      [graph]
    );

  // ============================================================
  // SERVICE LIST
  // ============================================================

  const services =
    useMemo(() => {
      const set =
        new Set();

      rawNodes.forEach(
        (node) => {
          const service =
            getNodeService(node);

          if (service) {
            set.add(service);
          }
        }
      );

      return [
        "ALL",
        ...Array.from(set).sort(),
      ];
    }, [rawNodes]);

  // ============================================================
  // FILTER NODES
  // ============================================================

  const filteredNodes =
    useMemo(() => {
      return rawNodes.filter(
        (node) => {
          if (
            !showFindings &&
            isFindingNode(node)
          ) {
            return false;
          }

          if (
            serviceFilter !==
              "ALL" &&
            getNodeService(node) !==
              serviceFilter
          ) {
            return false;
          }

          return true;
        }
      );
    }, [
      rawNodes,
      showFindings,
      serviceFilter,
    ]);

  // ============================================================
  // FILTER EDGES
  // ============================================================

  const filteredEdges =
    useMemo(() => {
      const nodeIds =
        new Set(
          filteredNodes.map(
            getNodeId
          )
        );

      return rawEdges.filter(
        (edge) => {
          if (
            verifiedOnly &&
            !isVerifiedEdge(edge)
          ) {
            return false;
          }

          return (
            nodeIds.has(
              getEdgeSource(edge)
            ) &&
            nodeIds.has(
              getEdgeTarget(edge)
            )
          );
        }
      );
    }, [
      rawEdges,
      filteredNodes,
      verifiedOnly,
    ]);

  // ============================================================
  // LAYOUT
  // ============================================================

  const layout =
    useMemo(
      () =>
        buildGraphLayout(
          filteredNodes,
          filteredEdges
        ),
      [
        filteredNodes,
        filteredEdges,
      ]
    );

  // ============================================================
  // GRAPH STATISTICS
  // ============================================================

  const graphNodeCount =
    number(
      summary?.node_count,
      rawNodes.length
    );

  const graphEdgeCount =
    number(
      summary?.edge_count,
      rawEdges.length
    );

  const findingCount =
    number(
      summary?.finding_count,
      rawNodes.filter(
        isFindingNode
      ).length
    );

  // ----------------------------------------------------------
  // IMPORTANT:
  // These come directly from backend summary.
  // ----------------------------------------------------------

  const internetExposed =
    number(
      summary?.internet_exposed_nodes,
      0
    );

  const privilegeRisk =
    number(
      summary?.privilege_escalation_nodes,
      0
    );

  const lateralMovement =
    number(
      summary?.lateral_movement_nodes,
      0
    );

  const backendAttackPathCount =
    number(
      summary?.attack_path_count,
      attackPaths.length
    );

  const verifiedRelationshipCount =
    number(
      analysis?.relationships?.verified_edge_count,
      graph?.relationship_count ??
        rawEdges.filter(
          isVerifiedEdge
        ).length
    );

  // ============================================================
  // DISCOVERY STATE
  // ============================================================

  const discoveryComplete =
    analysis?.discovery
      ?.complete ??
    analysis?.discovery_complete ??
    graph?.discovery
      ?.complete ??
    true;

  const graphSource =
    text(
      analysis?.graph_source ||
        graph?.graph_source ||
        "scan_level_security_graph"
    );

  const graphSchemaVersion =
    text(
      analysis
        ?.scan_graph_schema_version ||
        graph
          ?.graph_schema_version ||
        "2.0"
    );

  const engineVersion =
    text(
      analysis
        ?.graph_engine_version ||
        graph?.graph_engine_version ||
        "2.2"
    );

  const deterministic =
    analysis?.deterministic !==
      false;

  const verifiedEdgesOnly =
    analysis
      ?.verified_edges_only !==
      false;

  // ============================================================
  // RESET VIEW
  // ============================================================

  const resetView =
    () => {
      setZoom(0.6);

      setPan({
        x: 0,
        y: 0,
      });

      setSelectedNode(
        null
      );

      setSelectedEdge(
        null
      );
    };

  // ============================================================
  // NODE CLICK
  // ============================================================

  const loadResourceCorrelation =
    useCallback(
      async (node, overrideAccountId = "") => {
        const resourceId =
          getNodeId(node);

        const requestAccountId =
          text(overrideAccountId) ||
          text(accountId);

        if (!resourceId) {
          setCorrelation(null);
          setCorrelationError(
            "This graph node does not have a resource identifier."
          );
          return;
        }

        // Synthetic topology nodes such as PUBLIC_INTERNET are graph
        // anchors, not AWS resources owned by an account. They should
        // remain inspectable without forcing an account lookup.
        const nodeType = getNodeType(node);
        const syntheticNodeTypes = new Set([
          "INTERNET",
          "PUBLIC_INTERNET",
          "AWS_ACCOUNT",
        ]);

        if (syntheticNodeTypes.has(nodeType)) {
          setCorrelation({
            status: "topology_only",
            correlation: {
              mode: "TOPOLOGY_ONLY",
              remediation_available: false,
            },
            findings: {
              total: 0,
              active: 0,
              highest_severity: "NONE",
              risk_flags: {
                internet_exposed: false,
                privilege_escalation: false,
                lateral_movement: false,
              },
              items: [],
            },
            remediations: {
              active_proposals: 0,
              items: [],
            },
            graph: {
              verified_related_edge_count: 0,
            },
          });
          setCorrelationLoading(false);
          setCorrelationError("");
          return;
        }

        if (!requestAccountId) {
          setCorrelation(null);
          setCorrelationError(
            "Account context is unavailable for this AWS resource."
          );
          return;
        }

        const requestId =
          correlationRequestRef.current + 1;

        correlationRequestRef.current =
          requestId;

        setCorrelationLoading(true);
        setCorrelationError("");
        setCorrelation(null);

        try {
          const response =
            await api.get(
              `/security-correlation/resource/${encodeURIComponent(resourceId)}`,
              {
                params: {
                  account_id: requestAccountId,
                },
              }
            );

          if (
            correlationRequestRef.current ===
            requestId
          ) {
            setCorrelation(
              response?.data || null
            );
          }
        } catch (err) {
          console.error(
            "Security resource correlation error:",
            err
          );

          if (
            correlationRequestRef.current ===
            requestId
          ) {
            setCorrelationError(
              err?.response?.data?.detail ||
                "Unable to load resource security context."
            );
          }
        } finally {
          if (
            correlationRequestRef.current ===
            requestId
          ) {
            setCorrelationLoading(false);
          }
        }
      },
      [accountId]
    );

  const handleNodeClick =
    (node) => {
      setSelectedNode(
        node
      );

      setSelectedEdge(
        null
      );

      // Prefer the account identity attached to the selected graph node.
      // This prevents cross-account ambiguity when a tenant has multiple
      // AWS accounts represented in one graph.
      const nodeAccountId =
        extractAccountId(node);

      loadResourceCorrelation(
        node,
        nodeAccountId
      );
    };

  // ============================================================
  // EDGE CLICK
  // ============================================================

  const handleEdgeClick =
    (edge) => {
      setSelectedEdge(
        edge
      );

      setSelectedNode(
        null
      );
    };

  // ============================================================
  // NODE CONNECTION COUNT
  // ============================================================

  const connectionCount =
    (nodeId) => {
      return rawEdges.filter(
        (edge) =>
          getEdgeSource(edge) ===
            nodeId ||
          getEdgeTarget(edge) ===
            nodeId
      ).length;
    };

  // ============================================================
  // SELECTED NODE EDGES
  // ============================================================

  const selectedNodeEdges =
    useMemo(() => {
      if (!selectedNode) {
        return [];
      }

      const nodeId =
        getNodeId(
          selectedNode
        );

      return rawEdges.filter(
        (edge) =>
          getEdgeSource(edge) ===
            nodeId ||
          getEdgeTarget(edge) ===
            nodeId
      );
    }, [
      selectedNode,
      rawEdges,
    ]);

  // ============================================================
  // ATTACK PATH EMPTY STATE
  // ============================================================

  const attackPathEmpty =
    attackPaths.length === 0;

  // ============================================================
  // RENDER
  // ============================================================

  return (
    <div className="security-graph-page">

      {/* ======================================================
          PAGE HEADER
          ====================================================== */}

      <section className="security-graph-header">

        <div className="security-graph-title-wrap">

          <div className="security-graph-title-icon">
            <GitBranch size={28} />
          </div>

          <div>
            <div className="eyebrow">
              CLOUD SECURITY INTELLIGENCE
            </div>

            <h1>
              Security Graph
            </h1>

            <p>
              Evidence-backed AWS security topology
              and relationship intelligence.
            </p>
          </div>

        </div>


        <div className="security-graph-header-actions">

          <div
            className={`discovery-badge ${
              discoveryComplete
                ? "complete"
                : "warning"
            }`}
          >
            {discoveryComplete ? (
              <CheckCircle2
                size={15}
              />
            ) : (
              <AlertTriangle
                size={15}
              />
            )}

            <span>
              {discoveryComplete
                ? "Discovery Complete"
                : "Discovery Incomplete"}
            </span>
          </div>


          <button
            type="button"
            className="graph-refresh-btn"
            onClick={() =>
              loadGraph(true)
            }
            disabled={refreshing}
          >
            <RefreshCw
              size={16}
              className={
                refreshing
                  ? "spin"
                  : ""
              }
            />

            <span>
              {refreshing
                ? "Refreshing"
                : "Refresh"}
            </span>
          </button>

        </div>

      </section>


      {/* ======================================================
          ERROR
          ====================================================== */}

      {error && (
        <div className="graph-error">

          <AlertTriangle size={19} />

          <div>
            <strong>
              Security graph unavailable
            </strong>

            <span>
              {error}
            </span>
          </div>

          <button
            type="button"
            onClick={() =>
              loadGraph()
            }
          >
            Retry
          </button>

        </div>
      )}


      {/* ======================================================
          KPI CARDS
          ====================================================== */}

      <section className="graph-kpi-grid">

        <KpiCard
          label="GRAPH NODES"
          value={graphNodeCount}
          description="Resources + findings"
          icon={
            <Layers3 size={18} />
          }
          variant="neutral"
        />

        <KpiCard
          label="VERIFIED RELATIONSHIPS"
          value={
            verifiedRelationshipCount
          }
          description="Evidence-backed edges"
          icon={
            <GitBranch size={18} />
          }
          variant="blue"
        />

        <KpiCard
          label="INTERNET EXPOSED"
          value={internetExposed}
          description="Public exposure indicators"
          icon={
            <Cloud size={18} />
          }
          variant="orange"
        />

        <KpiCard
          label="PRIVILEGE RISK"
          value={privilegeRisk}
          description="Privilege escalation indicators"
          icon={
            <ShieldAlert size={18} />
          }
          variant="red"
        />

        <KpiCard
          label="ATTACK PATHS"
          value={backendAttackPathCount}
          description="Verified attack chains"
          icon={
            <Target size={18} />
          }
          variant="purple"
        />

      </section>


      {/* ======================================================
          TABS + FILTERS
          ====================================================== */}

      <section className="graph-toolbar">

        <div className="graph-tabs">

          <button
            type="button"
            className={
              activeTab === "overview"
                ? "active"
                : ""
            }
            onClick={() =>
              setActiveTab(
                "overview"
              )
            }
          >
            Overview
          </button>

          <button
            type="button"
            className={
              activeTab ===
              "attack-paths"
                ? "active"
                : ""
            }
            onClick={() =>
              setActiveTab(
                "attack-paths"
              )
            }
          >
            Attack Paths

            <span className="tab-count">
              {backendAttackPathCount}
            </span>
          </button>

        </div>


        {activeTab === "overview" && (
          <div className="graph-filters">

            <label className="service-select-wrap">

              <span>
                Service
              </span>

              <select
                value={
                  serviceFilter
                }
                onChange={(event) =>
                  setServiceFilter(
                    event.target.value
                  )
                }
              >
                {services.map(
                  (service) => (
                    <option
                      key={service}
                      value={service}
                    >
                      {service ===
                      "ALL"
                        ? "All Services"
                        : service}
                    </option>
                  )
                )}
              </select>

            </label>


            <label className="filter-check">

              <input
                type="checkbox"
                checked={
                  showFindings
                }
                onChange={(event) =>
                  setShowFindings(
                    event.target.checked
                  )
                }
              />

              <span>
                Findings
              </span>

            </label>


            <label className="filter-check">

              <input
                type="checkbox"
                checked={
                  verifiedOnly
                }
                onChange={(event) =>
                  setVerifiedOnly(
                    event.target.checked
                  )
                }
              />

              <span>
                Verified only
              </span>

            </label>

          </div>
        )}

      </section>


      {/* ======================================================
          LOADING
          ====================================================== */}

      {loading ? (
        <GraphLoading />
      ) : activeTab ===
        "attack-paths" ? (
        <AttackPathsPanel
          attackPaths={
            attackPaths
          }
          analysis={
            analysis
          }
          engineVersion={
            engineVersion
          }
        />
      ) : (

        /* ====================================================
           MAIN GRAPH AREA
           ==================================================== */

        <section className="graph-workspace">

          {/* ================================================
              GRAPH PANEL
              ================================================ */}

          <div className="graph-panel">

            <div className="graph-panel-header">

              <div>
                <span className="panel-eyebrow">
                  LIVE TOPOLOGY
                </span>

                <h2>
                  AWS Security Relationships
                </h2>
              </div>


              <div className="graph-source-badge">
                {graphSource}
              </div>

              <button
                type="button"
                className="graph-fullscreen-btn"
                title="Open graph fullscreen"
                onClick={() => document.querySelector(".graph-panel")?.requestFullscreen?.()}
              >
                <Maximize2 size={15} />
              </button>

            </div>


            {/* ==============================================
                LEGEND
                ============================================== */}

            <div className="graph-legend">

              <span>
                Relationships
              </span>

              <LegendItem
                label="EXPOSES"
                color={
                  RELATIONSHIP_COLORS.EXPOSES
                }
              />

              <LegendItem
                label="ASSUMES_ROLE"
                color={
                  RELATIONSHIP_COLORS.ASSUMES_ROLE
                }
              />

              <LegendItem
                label="GRANTS"
                color={
                  RELATIONSHIP_COLORS.GRANTS
                }
              />

              <LegendItem
                label="TRUSTS"
                color={
                  RELATIONSHIP_COLORS.TRUSTS
                }
              />

              <LegendItem
                label="CONNECTED_TO"
                color={
                  RELATIONSHIP_COLORS.CONNECTED_TO
                }
              />

            </div>


            {/* ==============================================
                GRAPH CANVAS
                ============================================== */}

            <div className="graph-canvas">

              <div className="graph-canvas-controls">

                <button
                  type="button"
                  title="Zoom in"
                  onClick={() =>
                    setZoom(
                      (value) =>
                        Math.min(
                          1.5,
                          value +
                            0.1
                        )
                    )
                  }
                >
                  <Plus size={15} />
                </button>

                <span>
                  {Math.round(
                    zoom * 100
                  )}
                  %
                </span>

                <button
                  type="button"
                  title="Zoom out"
                  onClick={() =>
                    setZoom(
                      (value) =>
                        Math.max(
                          0.25,
                          value -
                            0.1
                        )
                    )
                  }
                >
                  <Minus size={15} />
                </button>

                <button
                  type="button"
                  title="Reset graph"
                  onClick={
                    resetView
                  }
                >
                  <RefreshCw
                    size={15}
                  />
                </button>

              </div>


              <div
                className="graph-canvas-help"
              >
                Click nodes or
                relationships for evidence
              </div>


              {layout.nodes.length ===
              0 ? (

                <div className="graph-empty">
                  <div className="graph-empty-icon">
                    <GitBranch
                      size={25}
                    />
                  </div>

                  <h3>
                    No graph resources
                  </h3>

                  <p>
                    Run a cloud scan to
                    populate the security
                    relationship graph.
                  </p>
                </div>

              ) : (

                <div className="graph-viewport">

                  <div
                    className="graph-world"
                    style={{
                      width:
                        layout.width,
                      height:
                        layout.height,
                      transform:
                        `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
                    }}
                  >

                    {/* ========================================
                        EDGES
                        ======================================== */}

                    <svg
                      className="graph-edges"
                      style={{
                        position: "absolute",
                        inset: 0,
                        zIndex: 0,
                        pointerEvents: "none",
                      }}
                      width={
                        layout.width
                      }
                      height={
                        layout.height
                      }
                      viewBox={`0 0 ${layout.width} ${layout.height}`}
                    >

                      <defs>

                        <marker
                          id="arrow-default"
                          markerWidth="7"
                          markerHeight="7"
                          refX="6"
                          refY="3.5"
                          orient="auto"
                        >
                          <path
                            d="M0,0 L7,3.5 L0,7 Z"
                            fill="#94a3b8"
                          />
                        </marker>

                        {Object.entries(
                          RELATIONSHIP_COLORS
                        ).map(
                          ([
                            type,
                            color,
                          ]) => (
                            <marker
                              key={type}
                              id={`arrow-${type}`}
                              markerWidth="7"
                              markerHeight="7"
                              refX="6"
                              refY="3.5"
                              orient="auto"
                            >
                              <path
                                d="M0,0 L7,3.5 L0,7 Z"
                                fill={
                                  color
                                }
                              />
                            </marker>
                          )
                        )}

                      </defs>


                      {layout.edges.map(
                        (
                          edge,
                          index
                        ) => {

                          const source =
                            layout.positions.get(
                              getEdgeSource(
                                edge
                              )
                            );

                          const target =
                            layout.positions.get(
                              getEdgeTarget(
                                edge
                              )
                            );

                          if (
                            !source ||
                            !target
                          ) {
                            return null;
                          }

                          const type =
                            getEdgeType(
                              edge
                            );

                          const color =
                            getRelationshipColor(
                              type
                            );

                          const isSelected =
                            selectedEdge ===
                            edge;

                          const sourceX =
                            source.x +
                            NODE_WIDTH /
                              2;

                          const sourceY =
                            source.y +
                            NODE_HEIGHT /
                              2;

                          const targetX =
                            target.x +
                            NODE_WIDTH /
                              2;

                          const targetY =
                            target.y +
                            NODE_HEIGHT /
                              2;

                          const dx =
                            targetX -
                            sourceX;

                          const curve =
                            Math.max(
                              30,
                              Math.abs(
                                dx
                              ) *
                                0.18
                            );

                          const controlX =
                            sourceX +
                            dx /
                              2;

                          const path =
                            `M ${sourceX} ${sourceY} C ${controlX} ${sourceY - curve}, ${controlX} ${targetY + curve}, ${targetX} ${targetY}`;

                          return (
                            <g
                              key={
                                edge?.edge_id ||
                                edge?.id ||
                                `${getEdgeSource(
                                  edge
                                )}-${getEdgeTarget(
                                  edge
                                )}-${index}`
                              }
                              className={
                                isSelected
                                  ? "graph-edge selected"
                                  : "graph-edge"
                              }
                              onClick={() =>
                                handleEdgeClick(
                                  edge
                                )
                              }
                            >

                              <path
                                d={path}
                                stroke={
                                  color
                                }
                                strokeWidth={
                                  isSelected
                                    ? 3
                                    : 1.4
                                }
                                fill="none"
                                opacity={
                                  isSelected
                                    ? 1
                                    : 0.72
                                }
                                markerEnd={`url(#arrow-${type})`}
                              />

                            </g>
                          );
                        }
                      )}

                    </svg>


                    {/* ========================================
                        NODES
                        ======================================== */}

                    {layout.nodes.map(
                      (node) => {

                        const nodeId =
                          getNodeId(
                            node
                          );

                        const position =
                          layout.positions.get(
                            nodeId
                          );

                        if (
                          !position
                        ) {
                          return null;
                        }

                        const type =
                          getNodeType(
                            node
                          );

                        const Icon =
                          getNodeIcon(
                            type
                          );

                        const severity =
                          getSeverity(
                            node
                          );

                        const selected =
                          selectedNode &&
                          getNodeId(
                            selectedNode
                          ) ===
                            nodeId;

                        const links =
                          connectionCount(
                            nodeId
                          );

                        return (
                          <button
                            type="button"
                            key={
                              nodeId
                            }
                            className={`graph-node ${
                              selected
                                ? "selected"
                                : ""
                            } ${
                              isFindingNode(
                                node
                              )
                                ? "finding-node"
                                : ""
                            }`}
                            style={{
                              left: position.x,
                              top: position.y,
                              zIndex: 5,
                              position: "absolute",
                              pointerEvents: "auto",
                              cursor: "pointer",
                            }}
                            onClick={(event) => {
                              event.preventDefault();
                              event.stopPropagation();
                              handleNodeClick(node);
                            }}
                          >

                            <div className="graph-node-icon">
                              <Icon
                                size={17}
                              />
                            </div>


                            <div className="graph-node-content">

                              <strong
                                title={getNodeName(
                                  node
                                )}
                              >
                                {compact(
                                  getNodeName(
                                    node
                                  )
                                )}
                              </strong>

                              <span>
                                {type.replaceAll(
                                  "_",
                                  " "
                                )}
                              </span>

                            </div>


                            <div className="graph-node-links">
                              {links}{" "}
                              {links === 1
                                ? "link"
                                : "links"}
                            </div>


                            {severity && (
                              <span
                                className={`node-severity ${getSeverityClass(
                                  severity
                                )}`}
                              >
                                {severity}
                              </span>
                            )}

                          </button>
                        );
                      }
                    )}

                  </div>

                </div>
              )}

            </div>


            {/* ==============================================
                GRAPH FOOTER
                ============================================== */}

            <div className="graph-panel-footer">

              <span>
                Showing{" "}
                <strong>
                  {layout.nodes.length}
                </strong>{" "}
                of{" "}
                <strong>
                  {graphNodeCount}
                </strong>{" "}
                nodes
              </span>

              <span>
                <strong>
                  {layout.edges.length}
                </strong>{" "}
                verified relationships
              </span>

              <span>
                Engine{" "}
                <strong>
                  {engineVersion}
                </strong>
              </span>

            </div>

          </div>


          {/* ================================================
              DETAILS PANEL
              ================================================ */}

          <aside className="graph-details-panel">

            {selectedNode ? (

              <NodeDetails
                node={
                  selectedNode
                }
                edges={
                  selectedNodeEdges
                }
                nodes={
                  rawNodes
                }
                correlation={
                  correlation
                }
                correlationLoading={
                  correlationLoading
                }
                correlationError={
                  correlationError
                }
                onOpenFindings={() => {
                  const finding =
                    getArray(correlation?.findings?.items)
                      .find(
                        (item) =>
                          text(item?.finding_id) &&
                          !["RESOLVED", "IGNORED", "NOT_APPLICABLE"].includes(
                            upper(item?.status)
                          )
                      ) ||
                    getArray(correlation?.findings?.items)[0];

                  const findingId = text(finding?.finding_id);

                  if (findingId) {
                    window.location.assign(
                      `/findings?finding_id=${encodeURIComponent(findingId)}`
                    );
                    return;
                  }

                  window.location.assign("/findings");
                }}
                onOpenRemediation={() => {
                  const findings = getArray(
                    correlation?.findings?.items
                  );

                  const finding =
                    findings.find(
                      (item) =>
                        text(item?.finding_id) &&
                        !["RESOLVED", "IGNORED", "NOT_APPLICABLE"].includes(
                          upper(item?.status)
                        )
                    ) || findings[0];

                  const findingId = text(finding?.finding_id);

                  const params = new URLSearchParams();

                  if (findingId) {
                    params.set("finding_id", findingId);
                  }

                  const awsAccountId = text(
                    node?.aws_account_id ||
                      node?.awsAccountId ||
                      node?.account_id ||
                      node?.accountId
                  );

                  if (awsAccountId) {
                    params.set("account_id", awsAccountId);
                  }

                  const query = params.toString();

                  window.location.assign(
                    query ? `/remediation?${query}` : "/remediation"
                  );
                }}
                onSelectNode={handleNodeClick}
                onClose={() =>
                  setSelectedNode(
                    null
                  )
                }
              />

            ) : selectedEdge ? (

              <EdgeDetails
                edge={
                  selectedEdge
                }
                nodes={
                  rawNodes
                }
                onClose={() =>
                  setSelectedEdge(
                    null
                  )
                }
              />

            ) : (

              <GraphDetailsEmpty
                graphNodeCount={
                  graphNodeCount
                }
                findingCount={
                  findingCount
                }
                internetExposed={
                  internetExposed
                }
                privilegeRisk={
                  privilegeRisk
                }
                lateralMovement={
                  lateralMovement
                }
                deterministic={
                  deterministic
                }
                verifiedEdgesOnly={
                  verifiedEdgesOnly
                }
              />

            )}

          </aside>

        </section>
      )}


      {/* ======================================================
          FOOTER INTELLIGENCE
          ====================================================== */}

      {!loading &&
        activeTab ===
          "overview" && (

        <section className="graph-intelligence-strip">

          <div className="intelligence-item">

            <div className="intelligence-icon blue">
              <ShieldCheck
                size={18}
              />
            </div>

            <div>
              <strong>
                Evidence-backed analysis
              </strong>

              <span>
                Only verified AWS relationships
                are used for graph intelligence.
              </span>
            </div>

          </div>


          <div className="intelligence-item">

            <div className="intelligence-icon purple">
              <Bot size={18} />
            </div>

            <div>
              <strong>
                Deterministic engine
              </strong>

              <span>
                Security topology and attack-path
                decisions do not depend on AI.
              </span>
            </div>

          </div>


          <div className="intelligence-item">

            <div className="intelligence-icon green">
              <Activity
                size={18}
              />
            </div>

            <div>
              <strong>
                Graph schema {graphSchemaVersion}
              </strong>

              <span>
                Scan-level topology is used as the
                authoritative graph snapshot.
              </span>
            </div>

          </div>

        </section>
      )}

    </div>
  );
}


// ============================================================
// KPI CARD
// ============================================================

function KpiCard({
  label,
  value,
  description,
  icon,
  variant,
}) {
  return (
    <div
      className={`graph-kpi-card ${variant}`}
    >

      <div className="kpi-top">

        <span>
          {label}
        </span>

        <div className="kpi-icon">
          {icon}
        </div>

      </div>


      <strong className="kpi-value">
        {value}
      </strong>


      <span className="kpi-description">
        {description}
      </span>

    </div>
  );
}


// ============================================================
// LEGEND
// ============================================================

function LegendItem({
  label,
  color,
}) {
  return (
    <span className="legend-item">

      <span
        className="legend-dot"
        style={{
          background:
            color,
        }}
      />

      {label}

    </span>
  );
}


// ============================================================
// NODE DETAILS
// ============================================================

function NodeDetails({
  node,
  edges,
  nodes,
  correlation,
  correlationLoading,
  correlationError,
  onOpenFindings,
  onOpenRemediation,
  onSelectNode,
  onClose,
}) {
  const type =
    getNodeType(node);

  const Icon =
    getNodeIcon(type);

  const nodeId =
    getNodeId(node);

  const relatedIds =
    new Set();

  edges.forEach(
    (edge) => {
      const source =
        getEdgeSource(edge);

      const target =
        getEdgeTarget(edge);

      if (
        source === nodeId
      ) {
        relatedIds.add(
          target
        );
      }

      if (
        target === nodeId
      ) {
        relatedIds.add(
          source
        );
      }
    }
  );

  const relatedNodes =
    nodes.filter(
      (item) =>
        relatedIds.has(
          getNodeId(item)
        )
    ).slice(0, 8);

  return (
    <div className="details-content">

      <div className="details-header">

        <div className="details-title">

          <div className="details-node-icon">
            <Icon size={20} />
          </div>

          <div>
            <span>
              {type.replaceAll(
                "_",
                " "
              )}
            </span>

            <h3>
              {getNodeName(
                node
              )}
            </h3>
          </div>

        </div>


        <button
          type="button"
          className="details-close"
          onClick={
            onClose
          }
        >
          <X size={17} />
        </button>

      </div>


      <div className="evidence-badge">
        <CheckCircle2
          size={14}
        />

        Evidence-backed resource
      </div>


      <div className="details-section">

        <h4>
          Resource identity
        </h4>

        <DetailRow
          label="Resource ID"
          value={
            getNodeId(node)
          }
          mono
        />

        <DetailRow
          label="Service"
          value={
            getNodeService(
              node
            ) || "AWS"
          }
        />

        <DetailRow
          label="Region"
          value={
            text(
              node?.region ||
                node?.metadata
                  ?.region ||
                "—"
            )
          }
        />

        <DetailRow
          label="ARN"
          value={
            text(
              node?.resource_arn ||
                node?.arn ||
                "—"
            )
          }
          mono
        />

      </div>


      <div className="details-section">

        <h4>
          Relationship evidence
        </h4>

        <div className="relationship-summary">

          <div>
            <strong>
              {edges.length}
            </strong>

            <span>
              Connected relationships
            </span>
          </div>

          <div>
            <strong>
              {
                edges.filter(
                  isVerifiedEdge
                ).length
              }
            </strong>

            <span>
              Verified
            </span>
          </div>

        </div>

      </div>


      <div className="details-section">

        <div style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 12,
          marginBottom: 12,
        }}>
          <h4 style={{ margin: 0 }}>
            Security context
          </h4>

          <span style={{
            fontSize: 10,
            fontWeight: 800,
            letterSpacing: "0.06em",
            textTransform: "uppercase",
            color: "#64748b",
          }}>
            Correlated
          </span>
        </div>

        {correlationLoading ? (
          <div style={{
            padding: 14,
            border: "1px solid #e2e8f0",
            borderRadius: 12,
            color: "#64748b",
            fontSize: 12,
          }}>
            Loading findings and remediation context…
          </div>
        ) : correlationError ? (
          <div style={{
            padding: 14,
            border: "1px solid #fed7aa",
            background: "#fff7ed",
            borderRadius: 12,
            color: "#9a3412",
            fontSize: 12,
            lineHeight: 1.5,
          }}>
            {correlationError}
          </div>
        ) : correlation ? (
          <>
            <div style={{
              display: "grid",
              gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
              gap: 8,
              marginBottom: 12,
            }}>
              <div style={{ padding: 12, border: "1px solid #e2e8f0", borderRadius: 12 }}>
                <strong style={{ display: "block", fontSize: 18 }}>
                  {number(correlation?.findings?.total)}
                </strong>
                <span style={{ fontSize: 10, color: "#64748b" }}>Findings</span>
              </div>

              <div style={{ padding: 12, border: "1px solid #e2e8f0", borderRadius: 12 }}>
                <strong style={{ display: "block", fontSize: 18 }}>
                  {number(correlation?.findings?.active)}
                </strong>
                <span style={{ fontSize: 10, color: "#64748b" }}>Active risk</span>
              </div>

              <div style={{ padding: 12, border: "1px solid #e2e8f0", borderRadius: 12 }}>
                <strong style={{ display: "block", fontSize: 18 }}>
                  {number(correlation?.graph?.verified_related_edge_count)}
                </strong>
                <span style={{ fontSize: 10, color: "#64748b" }}>Verified edges</span>
              </div>

              <div style={{ padding: 12, border: "1px solid #e2e8f0", borderRadius: 12 }}>
                <strong style={{ display: "block", fontSize: 14, marginTop: 2 }}>
                  {text(correlation?.findings?.highest_severity, "NONE")}
                </strong>
                <span style={{ fontSize: 10, color: "#64748b" }}>Highest severity</span>
              </div>
            </div>

            <div style={{
              display: "flex",
              flexWrap: "wrap",
              gap: 6,
              marginBottom: 12,
            }}>
              {correlation?.findings?.risk_flags?.internet_exposed && (
                <span style={{ padding: "5px 8px", borderRadius: 999, background: "#fff7ed", color: "#c2410c", fontSize: 10, fontWeight: 800 }}>
                  INTERNET EXPOSED
                </span>
              )}
              {correlation?.findings?.risk_flags?.privilege_escalation && (
                <span style={{ padding: "5px 8px", borderRadius: 999, background: "#fef2f2", color: "#dc2626", fontSize: 10, fontWeight: 800 }}>
                  PRIVILEGE RISK
                </span>
              )}
              {correlation?.findings?.risk_flags?.lateral_movement && (
                <span style={{ padding: "5px 8px", borderRadius: 999, background: "rgba(245, 158, 11, 0.12)", color: "#fbbf24", fontSize: 10, fontWeight: 800 }}>
                  LATERAL MOVEMENT
                </span>
              )}
            </div>

            {getArray(correlation?.findings?.items).slice(0, 3).map((finding) => (
              <div key={text(finding?.finding_id || finding?.database_id)} style={{
                border: "1px solid #e2e8f0",
                borderRadius: 12,
                padding: 11,
                marginBottom: 8,
                background: "#ffffff",
              }}>
                <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                  <strong style={{ fontSize: 12, lineHeight: 1.35 }}>
                    {compact(finding?.issue || finding?.description || "Security finding")}
                  </strong>
                  <span className={`node-severity ${getSeverityClass(finding?.severity)}`}>
                    {text(finding?.severity, "LOW")}
                  </span>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", gap: 8, marginTop: 7, fontSize: 10, color: "#64748b" }}>
                  <span>{text(finding?.finding_id, "Finding")}</span>
                  <span>{text(finding?.status, "UNKNOWN")}</span>
                </div>
              </div>
            ))}

            {getArray(correlation?.findings?.items).length === 0 && (
              <div style={{ padding: 12, borderRadius: 12, background: "#f8fafc", color: "#64748b", fontSize: 11 }}>
                No findings are currently correlated with this resource.
              </div>
            )}

            {getArray(correlation?.remediations?.items).length > 0 && (
              <div style={{ marginTop: 10, padding: 11, borderRadius: 12, background: "#f0fdf4", border: "1px solid #bbf7d0", fontSize: 11, color: "#166534" }}>
                {number(correlation?.remediations?.active_proposals)} active remediation proposal(s).
              </div>
            )}

            <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
              <button type="button" onClick={onOpenFindings} style={{ flex: 1, border: "1px solid #cbd5e1", background: "#fff", borderRadius: 10, padding: "9px 10px", fontSize: 11, fontWeight: 800, cursor: "pointer" }}>
                <ExternalLink size={13} style={{ verticalAlign: "-2px", marginRight: 5 }} />
                View Findings
              </button>
              {correlation?.correlation?.remediation_available && (
                <button type="button" onClick={onOpenRemediation} style={{ flex: 1, border: "none", background: "#172554", color: "#fff", borderRadius: 10, padding: "9px 10px", fontSize: 11, fontWeight: 800, cursor: "pointer" }}>
                  <ShieldAlert size={13} style={{ verticalAlign: "-2px", marginRight: 5 }} />
                  Open Remediation
                </button>
              )}
            </div>
          </>
        ) : (
          <div style={{ padding: 12, borderRadius: 12, background: "#f8fafc", color: "#64748b", fontSize: 11 }}>
            Select a graph resource to load its security context.
          </div>
        )}

      </div>


      {relatedNodes.length >
        0 && (

        <div className="details-section">

          <h4>
            Related resources
          </h4>

          <div className="related-resource-list">

            {relatedNodes.map(
              (related) => (
                <button
                  type="button"
                  key={
                    getNodeId(
                      related
                    )
                  }
                  className="related-resource"
                  onClick={(event) => {
                    event.preventDefault();
                    event.stopPropagation();
                    if (onSelectNode) {
                      onSelectNode(related);
                    }
                  }}
                  style={{
                    width: "100%",
                    textAlign: "left",
                    border: "1px solid #e2e8f0",
                    background: "#fff",
                    cursor: "pointer",
                    display: "flex",
                    alignItems: "center",
                    gap: 10,
                  }}
                  title="Open resource security context"
                >

                  <CircleDot
                    size={14}
                  />

                  <div>

                    <strong>
                      {compact(
                        getNodeName(
                          related
                        )
                      )}
                    </strong>

                    <span>
                      {getNodeType(
                        related
                      ).replaceAll(
                        "_",
                        " "
                      )}
                    </span>

                  </div>

                </button>
              )
            )}

          </div>

        </div>
      )}

    </div>
  );
}


// ============================================================
// EDGE DETAILS
// ============================================================

function EdgeDetails({
  edge,
  nodes,
  onClose,
}) {
  const type =
    getEdgeType(
      edge
    );

  const sourceId =
    getEdgeSource(
      edge
    );

  const targetId =
    getEdgeTarget(
      edge
    );

  const source =
    nodes.find(
      (node) =>
        getNodeId(node) ===
        sourceId
    );

  const target =
    nodes.find(
      (node) =>
        getNodeId(node) ===
        targetId
    );

  const evidence =
    getEvidence(
      edge
    );

  const verified =
    isVerifiedEdge(
      edge
    );

  return (
    <div className="details-content">

      <div className="details-header">

        <div className="details-title">

          <div
            className="details-edge-icon"
            style={{
              color:
                getRelationshipColor(
                  type
                ),
            }}
          >
            <GitBranch
              size={21}
            />
          </div>

          <div>
            <span>
              RELATIONSHIP
            </span>

            <h3>
              {type}
            </h3>
          </div>

        </div>


        <button
          type="button"
          className="details-close"
          onClick={
            onClose
          }
        >
          <X size={17} />
        </button>

      </div>


      <div
        className={`evidence-badge ${
          verified
            ? "verified"
            : "unverified"
        }`}
      >
        {verified ? (
          <CheckCircle2
            size={14}
          />
        ) : (
          <Info size={14} />
        )}

        {verified
          ? "Verified evidence"
          : "Evidence not verified"}
      </div>


      <div className="edge-flow">

        <div className="edge-resource">

          <strong>
            {compact(
              getNodeName(
                source
              )
            )}
          </strong>

          <span>
            {getNodeType(
              source
            ).replaceAll(
              "_",
              " "
            )}
          </span>

        </div>


        <div
          className="edge-arrow"
          style={{
            color:
              getRelationshipColor(
                type
              ),
          }}
        >
          <ArrowRight
            size={22}
          />
        </div>


        <div className="edge-resource">

          <strong>
            {compact(
              getNodeName(
                target
              )
            )}
          </strong>

          <span>
            {getNodeType(
              target
            ).replaceAll(
              "_",
              " "
            )}
          </span>

        </div>

      </div>


      <div className="details-section">

        <h4>
          Evidence
        </h4>

        <DetailRow
          label="Relationship"
          value={type}
        />

        <DetailRow
          label="Verified"
          value={
            verified
              ? "Yes"
              : "No"
          }
        />

        <DetailRow
          label="Evidence source"
          value={
            text(
              evidence?.source ||
                evidence?.provider ||
                evidence?.method ||
                "AWS relationship inventory"
            )
          }
        />

        <DetailRow
          label="Confidence"
          value={
            text(
              evidence?.confidence ||
                "Verified"
            )
          }
        />

      </div>


      <div className="evidence-note">

        <ShieldCheck
          size={17}
        />

        <span>
          CloudGuardAI only treats verified
          relationship evidence as authoritative
          for security graph intelligence.
        </span>

      </div>

    </div>
  );
}


// ============================================================
// DETAIL ROW
// ============================================================

function DetailRow({
  label,
  value,
  mono = false,
}) {
  return (
    <div className="detail-row">

      <span>
        {label}
      </span>

      <strong
        className={
          mono
            ? "mono"
            : ""
        }
        title={text(value)}
      >
        {text(
          value,
          "—"
        )}
      </strong>

    </div>
  );
}


// ============================================================
// EMPTY DETAILS
// ============================================================

function GraphDetailsEmpty({
  graphNodeCount,
  findingCount,
  internetExposed,
  privilegeRisk,
  lateralMovement,
  deterministic,
  verifiedEdgesOnly,
}) {
  return (
    <div className="details-empty">

      <div className="details-empty-icon">
        <GitBranch
          size={25}
        />
      </div>

      <h3>
        Explore the security graph
      </h3>

      <p>
        Select an AWS resource or
        relationship to inspect verified
        security evidence.
      </p>


      <div className="details-stat-card">

        <div className="details-stat-icon">
          <ShieldCheck
            size={18}
          />
        </div>

        <div>
          <strong>
            Evidence-backed analysis
          </strong>

          <span>
            CloudGuardAI uses verified AWS
            relationships for graph intelligence.
          </span>
        </div>

      </div>


      <div className="details-mini-grid">

        <MiniStat
          label="Resources"
          value={
            graphNodeCount
          }
        />

        <MiniStat
          label="Findings"
          value={
            findingCount
          }
        />

        <MiniStat
          label="Exposed"
          value={
            internetExposed
          }
        />

        <MiniStat
          label="Privilege"
          value={
            privilegeRisk
          }
        />

        <MiniStat
          label="Lateral"
          value={
            lateralMovement
          }
        />

      </div>


      <div className="security-properties">

        <Property
          label="Verified edges only"
          value={
            verifiedEdgesOnly
          }
        />

        <Property
          label="Deterministic analysis"
          value={
            deterministic
          }
        />

      </div>

    </div>
  );
}


// ============================================================
// MINI STAT
// ============================================================

function MiniStat({
  label,
  value,
}) {
  return (
    <div className="mini-stat">

      <strong>
        {value}
      </strong>

      <span>
        {label}
      </span>

    </div>
  );
}


// ============================================================
// PROPERTY
// ============================================================

function Property({
  label,
  value,
}) {
  return (
    <div className="property-row">

      <span>
        {label}
      </span>

      <strong
        className={
          value
            ? "property-yes"
            : "property-no"
        }
      >
        {value
          ? "YES"
          : "NO"}
      </strong>

    </div>
  );
}


// ============================================================
// ATTACK PATHS
// ============================================================

function AttackPathsPanel({
  attackPaths,
  analysis,
  engineVersion,
}) {
  const noPathReason =
    text(
      analysis?.analysis_state ||
        "NO_COMPLETE_VERIFIED_ATTACK_PATH"
    );

  return (
    <section className="attack-paths-panel">

      <div className="attack-paths-header">

        <div>

          <span className="panel-eyebrow">
            DETERMINISTIC ANALYSIS
          </span>

          <h2>
            Verified Attack Paths
          </h2>

          <p>
            Attack paths are only reported when
            CloudGuardAI can prove the required
            relationship chain from AWS evidence.
          </p>

        </div>


        <div className="attack-engine-badge">
          Engine {engineVersion}
        </div>

      </div>


      {attackPaths.length ===
      0 ? (

        <div className="attack-empty">

          <div className="attack-empty-icon">
            <ShieldCheck
              size={31}
            />
          </div>

          <h3>
            No complete verified attack paths
          </h3>

          <p>
            CloudGuardAI found no complete
            evidence-backed attack chain in
            the current AWS topology.
          </p>


          <div className="attack-state">

            <span>
              Analysis state
            </span>

            <strong>
              {noPathReason}
            </strong>

          </div>


          <div className="attack-method">

            <div>
              <CheckCircle2
                size={17}
              />

              Internet entry evidence
            </div>

            <div>
              <CheckCircle2
                size={17}
              />

              Verified exposure relationships
            </div>

            <div>
              <CheckCircle2
                size={17}
              />

              Verified identity relationships
            </div>

            <div>
              <CheckCircle2
                size={17}
              />

              Complete chain required
            </div>

          </div>

        </div>

      ) : (

        <div className="attack-path-list">

          {attackPaths.map(
            (path, index) => (
              <AttackPathCard
                key={
                  path?.path_id ||
                  path?.id ||
                  index
                }
                path={
                  path
                }
                index={
                  index
                }
              />
            )
          )}

        </div>
      )}

    </section>
  );
}


// ============================================================
// ATTACK PATH CARD
// ============================================================

function AttackPathCard({
  path,
  index,
}) {
  const nodes =
    getArray(
      path?.nodes ||
        path?.path ||
        path?.resources
    );

  return (
    <article className="attack-path-card">

      <div className="attack-path-card-header">

        <div>
          <span>
            ATTACK PATH
          </span>

          <h3>
            Verified chain #{index + 1}
          </h3>
        </div>

        <span className="verified-pill">
          <CheckCircle2
            size={13}
          />

          Verified
        </span>

      </div>


      <div className="attack-chain">

        {nodes.map(
          (node, nodeIndex) => {

            const nodeName =
              typeof node ===
              "string"
                ? node
                : getNodeName(
                    node
                  );

            const nodeType =
              typeof node ===
              "string"
                ? ""
                : getNodeType(
                    node
                  );

            return (
              <div
                className="attack-chain-step"
                key={`${nodeName}-${nodeIndex}`}
              >

                <div className="attack-chain-node">

                  <strong>
                    {compact(
                      nodeName
                    )}
                  </strong>

                  {nodeType && (
                    <span>
                      {nodeType.replaceAll(
                        "_",
                        " "
                      )}
                    </span>
                  )}

                </div>

                {nodeIndex <
                  nodes.length -
                    1 && (
                  <ArrowRight
                    size={17}
                  />
                )}

              </div>
            );
          }
        )}

      </div>

    </article>
  );
}


// ============================================================
// LOADING
// ============================================================

function GraphLoading() {
  return (
    <section className="graph-loading">

      <div className="loading-header">

        <div className="skeleton large" />
        <div className="skeleton medium" />

      </div>


      <div className="loading-kpis">

        {Array.from(
          {
            length: 5,
          }
        ).map(
          (_, index) => (
            <div
              className="loading-card"
              key={index}
            >
              <div className="skeleton small" />
              <div className="skeleton number" />
              <div className="skeleton medium" />
            </div>
          )
        )}

      </div>


      <div className="loading-workspace">

        <div className="loading-graph">

          <div className="skeleton medium" />

          <div className="loading-node-grid">

            {Array.from(
              {
                length: 8,
              }
            ).map(
              (_, index) => (
                <div
                  className="loading-node"
                  key={index}
                >
                  <div className="skeleton circle" />

                  <div>
                    <div className="skeleton small" />
                    <div className="skeleton tiny" />
                  </div>
                </div>
              )
            )}

          </div>

        </div>


        <div className="loading-details">

          <div className="skeleton medium" />

          <div className="skeleton large" />

          <div className="skeleton medium" />

          <div className="skeleton medium" />

        </div>

      </div>

    </section>
  );
}


export default SecurityGraph;