# Mortis - A Self-Hosted Server for Moe Memos

A self-hosted server that provides [Memos 0.21.0 OpenAPI](https://mudkipme.github.io/mortis/) support for compatible apps like Moe Memos.

Currently, it is implemented to use the latest Memos server as a backend.

## Usage

The server can be started with the following command:

```bash
mortis [flags]
```

Available flags:

* `-addr string`: Listen address (default "0.0.0.0")
* `-port int`: Listen port (default 5231)
* `-grpc-addr string`: gRPC server address of Memos server (default "127.0.0.1:5230")

The `-grpc-addr` flag should point directly to your Memos instance. Reverse proxy is not currently supported since Mortis connects to Memos using the gRPC protocol, and gRPC-Web protocol is not yet implemented. However, Mortis itself can be placed behind a reverse proxy.

You can use the same domain for both Memos and Mortis by proxying paths with the `/api/v1/` prefix to Mortis.

### Nginx Configuration Example

Here is an example of an Nginx configuration to proxy requests to both Memos and Mortis:

```nginx
server {
    listen 80;
    server_name yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:5230; # Memos server
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /api/v1/ {
        proxy_pass http://127.0.0.1:5231; # Mortis server
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /o/r/ {
        proxy_pass http://127.0.0.1:5231; # Mortis server
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Docker Compose Example

Here is an example `docker-compose.yml` file to run both Memos and Mortis:

```yaml
services:
    memos:
        image: neosmemo/memos:0.25.0
        container_name: memos
        volumes:
            - ./data:/var/opt/memos
        ports:
            - "5230:5230"

    mortis:
        image: ghcr.io/mudkipme/mortis:0.25.0
        container_name: mortis
        ports:
            - "5231:5231"
        entrypoint: ["/app/mortis"]
        command: ["-grpc-addr=memos:5230"]
        depends_on:
            - memos
```

## License

[MIT](LICENSE)