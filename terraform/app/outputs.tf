output "cloud_run_service" {
  description = "Cloud Run service name."
  value       = google_cloud_run_v2_service.foxguard.name
}

output "cloud_run_uri" {
  description = "Cloud Run service URL."
  value       = google_cloud_run_v2_service.foxguard.uri
}
