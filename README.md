# MISP


### Container build

```
docker build . -t misp
```

### Container Run

```
docker run -it --rm \
    -v $(pwd)/misp_import.init:/misp/misp_import.init \
    misp --help
```
