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

resource "google_cloud_run_v2_service" "foxguard" {
  name     = var.service_name
  location = var.region

  template {
    service_account = var.runtime_service_account

    containers {
      image = var.container_image

      ports {
        container_port = 8080
      }

      env {
        name  = "DB_HOST"
        value = var.db_host
      }

      env {
        name  = "DB_USER"
        value = var.db_user
      }

      env {
        name  = "DB_NAME"
        value = var.db_name
      }

      env {
        name = "DB_PASSWORD"
        value_source {
          secret_key_ref {
            secret  = var.db_password_secret
            version = "latest"
          }
        }
      }
    }
  }
}

resource "google_cloud_run_v2_service_iam_member" "public_invoker" {
  project  = var.project_id
  location = google_cloud_run_v2_service.foxguard.location
  name     = google_cloud_run_v2_service.foxguard.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
