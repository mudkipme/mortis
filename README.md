# Mortis - A Self-Hosted Server for Moe Memos

A self-hosted server that provides [Memos 0.21.0 OpenAPI](https://mudkipme.github.io/mortis/) support for compatible apps like Moe Memos.

It uses Memos 26.10.0 as a backend, translating the legacy API to the current Memos HTTP API.

## Usage

The server can be started with the following command:

```bash
mortis [flags]
```

Available flags:

* `-addr string`: Listen address (default "0.0.0.0")
* `-port int`: Listen port (default 5231)
* `-grpc-addr string`: HTTP server address of Memos server (default "127.0.0.1:5230")

The `-grpc-addr` flag keeps its original name but connects over HTTP. Point it to your Memos instance (host and port, such as `memos:5230`). Mortis itself can also be placed behind a reverse proxy.

You can use the same domain for both Memos and Mortis by proxying `/api/v1/` and `/o/r/` to Mortis. Memos uses `/api/` for its current API.

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

### Caddy Configuration Example

Or if you prefer using caddy, here is an example of a configuration to proxy requests to both Memos and Mortis:

```caddyfile
yourdomain.com {
    reverse_proxy /api/v1/* mortis:5231
    reverse_proxy /o/r/* mortis:5231
    reverse_proxy memos:5230
}
```

### Docker Compose Example

Here is an example `docker-compose.yml` file to run both Memos and Mortis:

```yaml
services:
    memos:
        image: neosmemo/memos:26.10.0
        container_name: memos
        volumes:
            - ./data:/var/opt/memos
        ports:
            - "5230:5230"

    mortis:
        image: ghcr.io/mudkipme/mortis:26.10.0
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
