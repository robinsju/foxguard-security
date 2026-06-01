# FoxGuard Security Portal — Technical Architecture

## System Overview
The FoxGuard Security Portal is an automated, cloud-native incident management platform designed with strict isolation barriers, minimum privilege access controls, and a fully containerized deployment pipeline. 

## Component Breakdown
* **Frontend/Backend Routing Engine:** Built on Python 3.11 using the Flask framework. Handles user authorization loops and ticket creation dashboards.
* **Database Infrastructure:** Powered by a fully managed Google Cloud SQL PostgreSQL instance. The database is housed behind an isolated Virtual Private Cloud (VPC) network, completely hidden from the public internet.
* **Serverless Compute Layer:** Google Cloud Run dynamically scales the stateless Docker containers based on incoming HTTPS traffic, minimizing running costs and exposure footprints.
* **Secret Management Hub:** Sensitive credentials, database string keys, and authentication tokens are kept strictly inside GCP Secret Manager and injected at runtime rather than hardcoded into source control.

## Secure Identity Flow
Authentication between GitHub Actions pipelines and Google Cloud Platform utilizes OpenID Connect (OIDC) Workload Identity Federation. This eliminates long-lived, static IAM keys and instead requests transient, short-lived tokens to apply configurations safely.
