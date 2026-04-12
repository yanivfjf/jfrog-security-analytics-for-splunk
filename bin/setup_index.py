"""
Setup script for JFrog Security Analytics for Splunk.
Creates the required jfrog index if it does not exist.
"""
import sys
import splunk.entity as entity


def create_jfrog_index(session_key):
    """Create the jfrog index in Splunk if it does not already exist."""
    index_name = "jfrog"
    try:
        indexes = entity.getEntities(
            ["data", "indexes"],
            namespace="jfrog_security_analytics_for_splunk",
            owner="nobody",
            sessionKey=session_key,
        )
        if index_name not in indexes:
            new_index = entity.getEntity(
                ["data", "indexes"],
                "_new",
                namespace="jfrog_security_analytics_for_splunk",
                owner="nobody",
                sessionKey=session_key,
            )
            new_index["name"] = index_name
            new_index["maxTotalDataSizeMB"] = "51200"
            new_index["frozenTimePeriodInSecs"] = "7776000"
            entity.setEntity(new_index, sessionKey=session_key)
            print(f"Created index: {index_name}")
        else:
            print(f"Index already exists: {index_name}")
    except Exception as e:
        print(f"Error creating index: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: setup_index.py <session_key>", file=sys.stderr)
        sys.exit(1)
    create_jfrog_index(sys.argv[1])
