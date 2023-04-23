# Kenerl Pwn Env in Docker
## Usage
### Build
```bash
  docker-compose up --build -d
```
### Run
```bash
  # in the host
  docker-compose exec <docker-id> /bin/bash
  # remember to modify run.sh with $@ and core_modified.cpio
  <command to modify pwn/run.sh>
```

```bash
    # in the container
    exp.sh
```