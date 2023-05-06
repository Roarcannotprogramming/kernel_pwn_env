# Kenerl Pwn Env in Docker
## Usage
### Build
```bash
  docker-compose up --build -d
```
### Run
```bash
  # remember to modify run.sh with $@ and core_modified.cpio
  <command to modify pwn/run.sh>
  # start the qemu
  ./run.sh
  # start gdb
  ./gdb.sh
```