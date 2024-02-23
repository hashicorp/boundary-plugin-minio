# MinIO Plugin for HashiCorp Boundary

This repo contains the [MinIO](https://min.io) plugin for [HashiCorp
Boundary](https://www.boundaryproject.io/).

## Storage Bucket

This plugin supports storing, fetching and deleting objects from a MinIO
instance.

Files created with this plugin are stored as objects defined by the bucket name
and bucket prefix values configured in the storage bucket resource. These
storage bucket resources can in turn be associated to targets within Boundary.

During creation, update or deletion of a storage bucket handled by this plugin,
configuration is performed via attribute/secret key-value pairs. The values
received by this plugin are the attributes/secrets set on on a storage bucket in
Boundary.

The plugin fetches file metadata through the
[StatObject](https://min.io/docs/minio/linux/developers/go/API.html#StatObject)
call.

The plugin fetches files through the
[GetObject](https://min.io/docs/minio/linux/developers/go/API.html#GetObject)
call.

The plugin stores files through the
[PutObject](https://min.io/docs/minio/linux/developers/go/API.html#PutObject)
call.

The plugin deletes files through the
[RemoveObject](https://min.io/docs/minio/linux/developers/go/API.html#RemoveObject)
or
[RemoveObjectsWithResult](https://min.io/docs/minio/linux/developers/go/API.html#RemoveObjects)
calls.

For more details on using this plugin to store Boundary objects, see our
[getting started with MinIO storage buckets](plugin/service/storage/README.md)
guide.
