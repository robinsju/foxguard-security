# FoxGuard Security Portal

## 🏢 Company Profile
* **Company Name:** FoxGuard Security
* **Industry:** Cybersecurity / Cloud Security Operations
* **Description:** FoxGuard Security is a cloud-focused cybersecurity company specializing in cloud network defense, infrastructure hardening, vulnerability management, and security operations for small and medium-sized businesses.

---

## 💻 Application Overview
* **Application Name:** FoxGuard Security Portal
* **Application Type:** Cloud-Based Cybersecurity Ticket and Incident Management Dashboard
* **Problem Solved:** Provides a centralized dashboard where users can create, monitor, update, and resolve cybersecurity incidents and security-related tickets, establishing clear visibility into security operations.

---

## 👥 Team Members & Roles
* **Julia (`robinsju`)** — GitHub Repository / Project Coordination Lead
* **Ryan Quigley (`ryquigley`)** — Google Cloud / Terraform / Cloud Infrastructure Lead
* **Harrison (`harry0938`)** — Flask Application Developer
* **Abdul (`ghafoorhamdel`)** — Security / DevSecOps Workflow Lead

---

## 🛠️ Technology Stack
* **Frontend/Backend:** Flask, Bootstrap, PyMySQL
* **Database:** Google Cloud SQL for MySQL
* **Cloud Runtime:** Docker, Artifact Registry, Cloud Run
* **Infrastructure:** Terraform, Google Cloud VPC, Secret Manager
* **CI/CD & Security:** GitHub Actions, Workload Identity Federation/OIDC, SAST, container scanning

## Repository Evidence
* `.github/workflows/terraform-plan.yml` validates Terraform and runs a plan through GitHub Actions.
* `terraform/infrastructure/` defines project-level cloud resources such as Cloud SQL, Artifact Registry, Secret Manager, and Workload Identity.
* `terraform/app/` defines application deployment resources such as Cloud Run service settings.
* `docs/architecture.md` documents the required Cloud Run, Cloud SQL, VPC, Secret Manager, Artifact Registry, and OIDC flow.
