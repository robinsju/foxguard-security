output "artifact_registry_repository" {
  description = "Artifact Registry repository resource name."
  value       = google_artifact_registry_repository.foxguard.name
}

output "cloud_sql_instance" {
  description = "Cloud SQL instance connection name."
  value       = google_sql_database_instance.foxguard.connection_name
}

output "cloud_sql_database" {
  description = "Cloud SQL database name."
  value       = google_sql_database.foxguard.name
}

output "github_actions_service_account" {
  description = "Service account email used by GitHub Actions."
  value       = google_service_account.github_actions.email
}

output "workload_identity_provider" {
  description = "Full Workload Identity Provider resource path for GitHub repository variables."
  value       = google_iam_workload_identity_pool_provider.github.name
}
