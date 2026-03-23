RECON_CATEGORIES = frozenset({
    "account_discovery",
    "local_groups_discovery",
    "system_service_discovery",
    "system_information_discovery",
    "internet_connection_discovery",
    "remote_system_discovery",
    "system_users_discovery_od_access",
    "etc_hosts_access",
})

PERSIST_CATEGORIES = frozenset({
    "preferences_modification",
    "plist_file_modification",
    "data_collection_script",
    "launchctl_proc",
})

SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
