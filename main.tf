provider "google" {
    credentials = base64decode(var.GOOGLE_CREDENTIALS_CONTENT)
}

resource "google_cloudfunctions_function" "handle_webhook" {
    name = "handle_webhook"
    description = "Processes webhooks from Square"
    runtime = "python37"

    available_memory_mb = 128
    trigger_http = true
    entry_point = "handle_webhook"

    environment_variables = {
        SQUARE_WEBHOOK_SIGNATURE_KEY = var.SQUARE_WEBHOOK_SIGNATURE_KEY
    }
}

# IAM entry for all users to invoke the function
resource "google_cloudfunctions_function_iam_member" "invoker" {
  project        = google_cloudfunctions_function.handle_webhook.project
  region         = google_cloudfunctions_function.handle_webhook.region
  cloud_function = google_cloudfunctions_function.handle_webhook.name

  role   = "roles/cloudfunctions.invoker"
  member = "allUsers"
}

resource "google_pubsub_topic" "payment" {
  name = "orders"
}