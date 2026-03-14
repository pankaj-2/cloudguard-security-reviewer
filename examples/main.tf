terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

variable "project_id" {
  description = "GCP Project ID"
  type        = string
  default     = "my-gcp-project"
}

variable "region" {
  description = "GCP Region"
  type        = string
  default     = "us-central1"
}

# ── CRITICAL: Public access — allUsers granted owner role ──────────────────────
resource "google_project_iam_binding" "public_owner" {
  project = var.project_id
  role    = "roles/owner"           # CRITICAL: Owner role to allUsers

  members = [
    "allUsers",                     # CRITICAL: Publicly accessible
    "allAuthenticatedUsers",        # HIGH: Any Google account
  ]
}

# ── HIGH: Editor role granted too broadly ──────────────────────────────────────
resource "google_project_iam_binding" "broad_editor" {
  project = var.project_id
  role    = "roles/editor"          # HIGH: Overly broad write access

  members = [
    "user:developer@company.com",
    "user:contractor@external.com",  # HIGH: External user with editor
    "group:engineering@company.com",
  ]
}

# ── HIGH: Exported service account key — key material leaves GCP ────────────────
resource "google_service_account" "deploy_sa" {
  account_id   = "terraform-deploy-sa"
  display_name = "Terraform Deploy Service Account"
  project      = var.project_id
}

resource "google_service_account_key" "deploy_sa_key" {  # HIGH: Creates exported key
  service_account_id = google_service_account.deploy_sa.name
  public_key_type    = "TYPE_X509_PEM_FILE"
  # Key material exported and stored in Terraform state — HIGH risk
}

# ── MEDIUM: OS Login disabled on compute instance ──────────────────────────────
resource "google_compute_instance" "app_server" {
  name         = "app-server"
  machine_type = "e2-medium"
  zone         = "${var.region}-a"
  project      = var.project_id

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network = "default"
    access_config {
      # Ephemeral public IP — MEDIUM: public-facing instance
    }
  }

  metadata = {
    enable-oslogin            = "false"  # MEDIUM: OS Login disabled, falls back to SSH keys
    block-project-ssh-keys    = "false"  # MEDIUM: Project-wide SSH keys allowed
    serial-port-enable        = "true"   # LOW: Serial port console enabled
  }

  service_account {
    email  = google_service_account.deploy_sa.email
    scopes = ["cloud-platform"]          # HIGH: Full cloud-platform scope
  }

  tags = ["http-server", "https-server"]
}

# ── HIGH: Storage bucket without uniform bucket-level access ───────────────────
resource "google_storage_bucket" "app_data" {
  name          = "${var.project_id}-app-data"
  location      = "US"
  project       = var.project_id
  force_destroy = true               # MEDIUM: Allows non-empty bucket deletion

  uniform_bucket_level_access = false  # HIGH: Object-level ACLs enabled — ACL bypass risk

  versioning {
    enabled = false                  # MEDIUM: No versioning for recovery
  }

  lifecycle_rule {
    condition {
      age = 365
    }
    action {
      type = "Delete"
    }
  }
}

# ── MEDIUM: Firewall rule allows all traffic from Internet ─────────────────────
resource "google_compute_firewall" "allow_all_ingress" {
  name    = "allow-all-from-internet"
  network = "default"
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]           # CRITICAL: All ports open
  }

  source_ranges = ["0.0.0.0/0"]     # CRITICAL: Any source IP

  direction = "INGRESS"
}

# ── OK: Properly scoped service account ───────────────────────────────────────
resource "google_service_account" "gcs_reader" {
  account_id   = "gcs-reader-sa"
  display_name = "GCS Read-Only Service Account"
  project      = var.project_id
}

resource "google_project_iam_member" "gcs_reader_binding" {
  project = var.project_id
  role    = "roles/storage.objectViewer"  # OK: Minimal required role
  member  = "serviceAccount:${google_service_account.gcs_reader.email}"
}
