"""Freeze get_build_logs / get_runtime_logs GraphQL signatures from main @ 0b8959b."""

from graphql_ops import Q_GET_BUILD_LOGS, Q_GET_RUNTIME_LOGS

# Exact operations shipped on shanshan0530/zeabur-mcp main
# 0b8959b28354124c307cfa4c2f36245e3568f2e3 — do not "align" with official SDK.

FROZEN_RUNTIME_LOGS = """
            query RuntimeLogs($projectID: ObjectID!, $serviceID: ObjectID!, $environmentID: ObjectID!) {
              runtimeLogs(projectID: $projectID, serviceID: $serviceID, environmentID: $environmentID) {
                message
                timestamp
              }
            }
        """

FROZEN_BUILD_LOGS = """
            query BuildLogs($projectID: ObjectID!, $deploymentID: ObjectID!) {
              buildLogs(projectID: $projectID, deploymentID: $deploymentID) {
                message
                timestamp
              }
            }
        """


def test_runtime_logs_query_shape_unchanged():
    assert Q_GET_RUNTIME_LOGS == FROZEN_RUNTIME_LOGS
    assert "timestampCursor" not in Q_GET_RUNTIME_LOGS
    assert "deploymentID: $deploymentId" not in Q_GET_RUNTIME_LOGS
    assert "$projectID: ObjectID!" in Q_GET_RUNTIME_LOGS
    assert "projectID: $projectID" in Q_GET_RUNTIME_LOGS


def test_build_logs_query_shape_unchanged():
    assert Q_GET_BUILD_LOGS == FROZEN_BUILD_LOGS
    assert "$projectID: ObjectID!" in Q_GET_BUILD_LOGS
    assert "$deploymentID: ObjectID!" in Q_GET_BUILD_LOGS
    assert "buildLogs(projectID: $projectID, deploymentID: $deploymentID)" in Q_GET_BUILD_LOGS
    assert "timestampCursor" not in Q_GET_BUILD_LOGS
    # Official SDK omits projectID; Phase A must not adopt that signature.
    assert "buildLogs(deploymentID:" not in Q_GET_BUILD_LOGS.replace(" ", "")
