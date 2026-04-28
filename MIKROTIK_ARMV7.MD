### Build for a 32bit ARM Mikrotik device
`docker build --platform linux/arm/v7 -t mikrotik-blocklist:armv7 --load  .`
`# Note: tar files generate with docker save are not accepted by Mikrotik, skopeo seems to work`
`skopeo copy docker-daemon:mikrotik-blocklist:armv7 docker-archive:blocklist.tar0`
`scp blocklist.tar admin@mikrotik:/usb1`
`ssh admin@mikrotik`

On the Mikrotik device
`/interface/bridge/add name=containers`
`/ip/address/add interface=containers address=172.17.0.1/24`
`/interface/veth/add name=veth2 address=172.17.0.3/24 gateway=172.17.0.1`
`/interface/bridge/port/add bridge=containers interface=veth2`

`/container/add file=/usb1/blocklist.tar interface=veth2 start-on-boot=yes name="mikrotik-blocklist" root-dir=/usb1/mikrotik-blocklist logging=yes auto-restart-interval=none`
`/log/print where topics~"container"`
`/container/print`
 `# Wait until the status of the container is 'S'`
`/container/start mikrotik-blocklist`
 `/file/remove usb1/blocklist.tar`
