schema_version = 1

project {
  license        = "MPL-2.0"
  copyright_year = 2025

  header_ignore = [
    # ignoring Minio's apache licensed code that is used as is in this repo
    "madmin/**",
  ]
}
