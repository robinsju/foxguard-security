variable "project_id" {
  description = "Google Cloud project ID."
  type        = string
}

variable "region" {
  description = "Cloud Run region."
  type        = string
  default     = "us-central1"
}

variable "service_name" {
  description = "Cloud Run service name."
  type        = string
  default     = "foxguard-security-portal"
}

variable "container_image" {
  description = "Artifact Registry image deployed to Cloud Run."
  type        = string
  default     = "us-central1-docker.pkg.dev/foxguard-security/foxguard-containers/foxguard-security:latest"
}

variable "runtime_service_account" {
  description = "Runtime service account email for Cloud Run."
  type        = string
  default     = null
}

variable "db_host" {
  description = "Cloud SQL database host or connector endpoint."
  type        = string
  default     = "127.0.0.1"
}

variable "db_user" {
  description = "Database username."
  type        = string
  default     = "foxguarduser"
}

variable "db_name" {
  description = "Database name."
  type        = string
  default     = "foxguard"
}

variable "db_password_secret" {
  description = "Secret Manager secret containing the database password."
  type        = string
  default     = "foxguard-db-password"
}
