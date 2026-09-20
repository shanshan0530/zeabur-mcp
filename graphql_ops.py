"""Zeabur GraphQL documents used by MCP tools.

GRAPHQL_DOCUMENTS remains query-only. Write mutations live in MUTATION_DOCUMENTS
and must not be inlined in main.py.

Log query strings for get_runtime_logs / get_build_logs are frozen copies of
the operations shipped on main @ 0b8959b28354124c307cfa4c2f36245e3568f2e3.
"""

# Existing tools (signatures frozen for logs) --------------------------------

Q_LIST_PROJECTS = """
            query {
              projects(skip: 0, limit: 100) {
                edges {
                  node {
                    _id
                    name
                    environments { _id name }
                  }
                }
              }
            }
        """

Q_LIST_SERVICES = """
            query ListServices($projectID: ObjectID!) {
              services(projectID: $projectID) {
                edges {
                  node { _id name }
                }
              }
            }
        """

Q_GET_RUNTIME_LOGS = """
            query RuntimeLogs($projectID: ObjectID!, $serviceID: ObjectID!, $environmentID: ObjectID!) {
              runtimeLogs(projectID: $projectID, serviceID: $serviceID, environmentID: $environmentID) {
                message
                timestamp
              }
            }
        """

Q_GET_DEPLOYMENTS = """
            query Deployments($serviceID: ObjectID!, $environmentID: ObjectID!) {
              deployments(serviceID: $serviceID, environmentID: $environmentID) {
                edges {
                  node { _id status createdAt }
                }
              }
            }
        """

Q_GET_BUILD_LOGS = """
            query BuildLogs($projectID: ObjectID!, $deploymentID: ObjectID!) {
              buildLogs(projectID: $projectID, deploymentID: $deploymentID) {
                message
                timestamp
              }
            }
        """

Q_SCAN_PROJECTS = """
            query {
              projects(skip: 0, limit: 100) {
                edges {
                  node {
                    _id name
                    environments { _id name }
                  }
                }
              }
            }
        """

Q_SCAN_SERVICES = """
                query($projectID: ObjectID!) {
                  services(projectID: $projectID) {
                    edges { node { _id name } }
                  }
                }
            """

Q_SCAN_RUNTIME_LOGS = """
                query($projectID: ObjectID!, $serviceID: ObjectID!, $environmentID: ObjectID!) {
                  runtimeLogs(projectID: $projectID, serviceID: $serviceID, environmentID: $environmentID) {
                    message timestamp
                  }
                }
            """

# New Phase A tools — conservative field sets from the approved scope design.

Q_GET_SERVICE = """
            query GetService($id: ObjectID!) {
              service(_id: $id) {
                _id
                name
                status
                domains {
                  domain
                  status
                }
              }
            }
        """

Q_LIST_REGIONS = """
            query ListServers {
              servers {
                _id
                name
                country
                city
                status {
                  isOnline
                }
              }
            }
        """

Q_GET_ME = """
            query GetMe {
              me {
                _id
                username
                email
              }
            }
        """

# Key-only lookup for env writes. Never request current values.
Q_SERVICE_VARIABLE_KEYS = """
            query ServiceVariableKeys($serviceID: ObjectID!, $environmentID: ObjectID!) {
              service(_id: $serviceID) {
                variables(environmentID: $environmentID) {
                  key
                }
              }
            }
        """

# Map of every GraphQL query the MCP tools may send. Query-only.
GRAPHQL_DOCUMENTS = {
    "list_projects": Q_LIST_PROJECTS,
    "list_services": Q_LIST_SERVICES,
    "get_runtime_logs": Q_GET_RUNTIME_LOGS,
    "get_deployments": Q_GET_DEPLOYMENTS,
    "get_build_logs": Q_GET_BUILD_LOGS,
    "scan_all_logs.projects": Q_SCAN_PROJECTS,
    "scan_all_logs.services": Q_SCAN_SERVICES,
    "scan_all_logs.runtime_logs": Q_SCAN_RUNTIME_LOGS,
    "get_service": Q_GET_SERVICE,
    "list_regions": Q_LIST_REGIONS,
    "get_me": Q_GET_ME,
    "service_variable_keys": Q_SERVICE_VARIABLE_KEYS,
}

# Approved write mutations only. Do not add restart, deploy-from-spec,
# bulk env-var map updates, or delete-variable operations.
M_REDEPLOY_SERVICE = """
            mutation RedeployService(
              $serviceID: ObjectID!,
              $environmentID: ObjectID!
            ) {
              redeployService(
                serviceID: $serviceID,
                environmentID: $environmentID
              )
            }
        """

M_CREATE_ENVIRONMENT_VARIABLE = """
            mutation CreateEnvironmentVariable(
              $serviceID: ObjectID!,
              $environmentID: ObjectID!,
              $key: String!,
              $value: String!
            ) {
              createEnvironmentVariable(
                serviceID: $serviceID,
                environmentID: $environmentID,
                key: $key,
                value: $value
              )
            }
        """

M_UPDATE_SINGLE_ENVIRONMENT_VARIABLE = """
            mutation UpdateSingleEnvironmentVariable(
              $serviceID: ObjectID!,
              $environmentID: ObjectID!,
              $oldKey: String!,
              $newKey: String!,
              $value: String!
            ) {
              updateSingleEnvironmentVariable(
                serviceID: $serviceID,
                environmentID: $environmentID,
                oldKey: $oldKey,
                newKey: $newKey,
                value: $value
              )
            }
        """

MUTATION_DOCUMENTS = {
    "redeploy_service": M_REDEPLOY_SERVICE,
    "create_environment_variable": M_CREATE_ENVIRONMENT_VARIABLE,
    "update_single_environment_variable": M_UPDATE_SINGLE_ENVIRONMENT_VARIABLE,
}
