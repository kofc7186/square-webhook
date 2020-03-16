provider "google" {
    credentials = base64decode(var.GOOGLE_CREDENTIALS_CONTENT)
    region = "us-central1"
}

terraform {
    backend "gcs" {
        bucket = "kofc7186-fishfry"
        prefix = "square-webhook-tfstate"
    }
}

resource "google_cloudfunctions_function" "handle_webhook" {
    name = "handle_webhook"
    description = "Processes webhooks from Square"
    runtime = "python37"

    available_memory_mb = 128
    trigger_http = true
    timeout = 3
    entry_point = "handle_webhook"

    source_archive_bucket = google_storage_bucket.kofc7186-fishfry.name
    source_archive_object = google_storage_bucket_object.square-webhook-cloudfunction.name

    environment_variables = {
        SQUARE_WEBHOOK_SIGNATURE_KEY = var.SQUARE_WEBHOOK_SIGNATURE_KEY
    }
}

resource "google_storage_bucket" "kofc7186-fishfry" {
  name = "kofc7186-fishfry"
}

data "archive_file" "square-webhook-cloudfunction" {
  type        = "zip"
  output_path = "${path.module}/square-webhook-cloudfunction.zip"
  source {
    content  = "${file("${path.module}/main.py")}"
    filename = "main.py"
  }
  source {
    content  = "${file("${path.module}/requirements.txt")}"
    filename = "requirements.txt"
  }
}

resource "google_storage_bucket_object" "archive" {
  name   = "square-webhook-cloudfunction.zip"
  bucket = google_storage_bucket.bucket.name
  source = "${path.module}/square-webhook-cloudfunction.zip"
  depends_on = [data.archive_file.square-webhook-cloudfunction]
}

# IAM entry for all users to invoke the function
resource "google_cloudfunctions_function_iam_member" "invoker" {
  project        = google_cloudfunctions_function.handle_webhook.project
  region         = google_cloudfunctions_function.handle_webhook.region
  cloud_function = google_cloudfunctions_function.handle_webhook.name

  role   = "roles/cloudfunctions.invoker"
  member = "allUsers"
}

resource "google_pubsub_topic" "orders" {
  name = "orders"
}