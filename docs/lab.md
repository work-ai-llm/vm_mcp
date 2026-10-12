# The lab

Target: the GOAD (Get Off Attack Domain) lab on **VMware Workstation 17.5.2**.
The live registry has **8 VMs**, not the 6 the original plan assumed — the wazuh
monitor and the Ubuntu 22.04 image VM were already registered on this host:

| Registry name | Role | vCPU | RAM | Guest OS |
|---|---|---|---|---|
| `provider: GOAD-DC01` | domain controller, `sevenkingdoms.local` | 2 | 3000 MB | Windows Server 2019 |
| `provider: GOAD-DC02` | domain controller, `north.sevenkingdoms.local` | 2 | 3000 MB | Windows Server 2019 |
| `provider: GOAD-DC03` | domain controller, `essos.local` | 2 | 3000 MB | Windows Server 2019 |
| `provider: GOAD-SRV02` | server, `north.sevenkingdoms.local` | 2 | 6000 MB | Windows Server 2019 |
| `provider: GOAD-SRV03` | server, `essos.local` | 2 | 5000 MB | Windows Server 2019 |
| `provider: PROVISIONING` | Linux jumpbox / provisioner (Ubuntu 22.04) | 2 | 2000 MB | Ubuntu 22.04 |
| `wazuh-4.7.5` | Wazuh manager | 4 | 8192 MB | Linux (unclassified by VMware) |
| `Ubuntu_20.04.4_VM_LinuxVMImages.COM` | stock Ubuntu image | 2 | 4096 MB | Ubuntu 20.04 |

Note the `provider: ` prefix: that is Vagrant's naming, not VMware's, and it is
why `vm_status(name="GOAD-DC01")` has to work as well as the registry's own
spelling. The Server 2019 labels come from each `.vmx`; the registry's own
`guest` field claims 2016 for three of them and is not read.

The GOAD lab alone asks for ~21.5 GB of RAM against ~32 GB of physical memory on
a 4-core host, so all five lab VMs cannot be powered on at once — capacity
reporting must be honest per-VM rather than assume the lab fits. And a guest
takes roughly 156 seconds from power-on to a responsive SSH service, so a
`start_vm` that returns in under two seconds describes a VM that is useless for
another two and a half minutes. Both are why the health check exists and why the
timings are measured rather than assumed.

The registry is not scoped to this lab — it is everything registered with VMware
on the host — so `list_vms` reports all 8 VMs. See
[ADR 0002](decisions/0002-roster-and-list_vms.md).
