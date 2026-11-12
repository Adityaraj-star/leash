# One static binary; the dashboard is embedded in it.
FROM golang:1.27.4 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/leash ./cmd/leash

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/leash /leash
# Real mode by default. render.yaml overrides this with `serve -fake` for the hosted demo.
CMD ["/leash", "serve", "-data", "/data", "-merchants", "/etc/secrets/merchants.json"]
