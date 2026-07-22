# traefik-s3-proxy-plugin

This plugin is based on [craigbrogle/traefik-s3-plugin](https://github.com/craigbrogle/traefik-s3-plugin) code.

## Changelog

### s3-proxy 1.1.1

- Fixed AWS SigV4 object key escaping for reserved characters in paths (`$`, `&`, `:`, `;`, `=`, `@`, `+`) to prevent `SignatureDoesNotMatch` with S3-compatible backends (including Yandex Object Storage).
- Fixed response header forwarding: `Content-Length` is now set only when the upstream S3 response contains a non-empty value.

### s3-proxy 1.1.0

- Fixed incorrect handling of object keys containing `/`

### s3-proxy 1.0.0

- The code has been improved
- Added the ability to select the endpoint type for a bucket:
  `https://bucket.endpoit/prefix/key` or `https://endpoint/bucket/prefix/key`

### Usage (example for Yandex Cloud)

```yaml
http:
  middlewares:
    s3-get:
      plugin:
        s3-proxy:
          Service: s3
          EndpointUrl: storage.yandexcloud.net
          Region: ru-central1
          AccessKeyID: xxxxxxxxxxxxxxxx
          SecretAccessKey: xxxxxxxxxxxxxxxx
          Bucket: some.bucket.name
          LinkStyle: path
  
  routers:
    gmc:
      entryPoints:
        - websecure
      rule: Host(`example.com`)
      service: noop@internal
      middlewares:
        - s3-get
      tls: {}
```
