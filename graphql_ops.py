"""Read-only Zeabur GraphQL documents used by MCP tools.

Every document in this module must be a GraphQL `query`. Phase A does not
authorize mutations. Tests import GRAPHQL_DOCUMENTS and fail if a mutation
is introduced.

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

# Map of every GraphQL document the MCP tools may send.
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
}
