terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.45"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

resource "google_artifact_registry_repository" "foxguard" {
  location      = var.region
  repository_id = var.artifact_repository
  description   = "Docker images for the FoxGuard Security Portal"
  format        = "DOCKER"
}

resource "google_compute_network" "foxguard" {
  name                    = "foxguard-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "foxguard" {
  name          = "foxguard-subnet"
  ip_cidr_range = "10.20.0.0/24"
  network       = google_compute_network.foxguard.id
  region        = var.region
}

resource "google_sql_database_instance" "foxguard" {
  name             = var.sql_instance_name
  database_version = "MYSQL_8_0"
  region           = var.region

  settings {
    tier              = var.sql_tier
    availability_type = "ZONAL"
    disk_size         = 10
    disk_type         = "PD_SSD"

    ip_configuration {
      ipv4_enabled = true
    }
  }
}

resource "google_sql_database" "foxguard" {
  name     = var.sql_database_name
  instance = google_sql_database_instance.foxguard.name
}

resource "google_sql_user" "foxguard" {
  name     = var.sql_user
  instance = google_sql_database_instance.foxguard.name
  password = var.sql_password
}

resource "google_secret_manager_secret" "db_password" {
  secret_id = "foxguard-db-password"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "db_password" {
  secret      = google_secret_manager_secret.db_password.id
  secret_data = var.sql_password
}

resource "google_service_account" "github_actions" {
  account_id   = var.github_service_account_id
  display_name = "FoxGuard GitHub Actions deployer"
}

resource "google_iam_workload_identity_pool" "github" {
  workload_identity_pool_id = var.workload_identity_pool_id
  display_name              = "FoxGuard GitHub Actions pool"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = var.workload_identity_provider_id
  display_name                       = "GitHub Actions OIDC provider"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.actor"      = "assertion.actor"
    "attribute.repository" = "assertion.repository"
    "attribute.ref"        = "assertion.ref"
  }

  attribute_condition = "attribute.repository == '${var.github_repository}'"

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}
