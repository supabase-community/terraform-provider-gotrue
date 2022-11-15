terraform {
  required_providers {
    gotrue = {
      version = "0.0.1"
      source = "supabase.com/com/gotrue"
    }
  }
}

provider "gotrue" {
  url = "http://localhost:9999"
  headers = {
    Authorization = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imx5emJpY29jb3RyaWNvamxpaWR4Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTY1ODE0MTE2MywiZXhwIjoxOTczNzE3MTYzfQ.cKs4DOJUJ4R12OG0RsLp2M5mXaNqZDhWAny149E-kA8"
  }
}

resource "gotrue_saml_identity_provider" "samltest_id" {
  metadata_url = "https://samltest.id/saml/idp"
  domains = [ "example.com", "samltest.id" ]
  attribute_mapping = jsonencode({
    keys = {
      user_name = {
        name = "mail"
      }
    }
  })
}
