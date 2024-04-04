## Getting Started

To create a storage bucket (using default scope created by `boundary dev`):

```bash
boundary storage-buckets create \
  -scope-id p_1234567890 \
  -name "Example Plugin-Based Storage Bucket" \
  -description "Description for plugin-based storage bucket" \
  -plugin-name minio \
  -bucket-name="session_recording_storage" \
  -bucket-prefix="foo/bar/zoo" \
  -worker-filter '"minio-access" in "/tags/type"' \
  -attr endpoint_url="https://my-minio-instance.dev/s3-api" \
  -attr region=REGION \
  -attr disable_credential_rotation=true \
  -secret access_key_id='KEY' \
  -secret secret_access_key='SECRET'
```

### Attributes

The following `attributes` are valid on a MinIO storage bucket resource:

- `endpoint_url` (string, required): Fully-qualified endpoint pointing to a
  MinIO S3 API.
- `region` (string, optional): The region to configure the storage bucket for.
- `disable_credential_rotation` (bool, optional): Controls whether the plugin
  will rotate the incoming credentials and manage a new MinIO service account.
  If this attribute is set to `false`, or not provided, the plugin will rotate
  the incoming credentials, using them to create a new MinIO service account,
  then delete the incoming credentials.

### Secrets

The following `secrets` are valid on a MinIO storage bucket resource:

- `access_key_id` (string, required): The MinIO service account's access key to
  use with this storage bucket.
- `secret_access_key` (string, required): The MinIO service account's secret key
  to use with this storage bucket.
