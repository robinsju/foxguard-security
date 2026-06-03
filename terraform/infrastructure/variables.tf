variable "project_id" {
  description = "Google Cloud project ID."
  type        = string
}

variable "region" {
  description = "Primary Google Cloud region."
  type        = string
  default     = "us-central1"
}

variable "artifact_repository" {
  description = "Artifact Registry Docker repository name."
  type        = string
  default     = "foxguard-containers"
}

variable "sql_instance_name" {
  description = "Cloud SQL instance name."
  type        = string
  default     = "foxguard-db"
}

variable "sql_database_name" {
  description = "Application database name."
  type        = string
  default     = "foxguard"
}

variable "sql_user" {
  description = "Application database user."
  type        = string
  default     = "foxguarduser"
}

variable "sql_password" {
  description = "Application database password."
  type        = string
  sensitive   = true
}

variable "sql_tier" {
  description = "Cloud SQL machine tier."
  type        = string
  default     = "db-f1-micro"
}

variable "github_repository" {
  description = "GitHub repository allowed to use the OIDC provider."
  type        = string
  default     = "robinsju/foxguard-security"
}

variable "github_service_account_id" {
  description = "Service account used by GitHub Actions."
  type        = string
  default     = "foxguard-deployer"
}

variable "workload_identity_pool_id" {
  description = "Workload Identity Federation pool ID."
  type        = string
  default     = "foxguard-pool"
}

variable "workload_identity_provider_id" {
  description = "Workload Identity Federation provider ID."
  type        = string
  default     = "github"
}
