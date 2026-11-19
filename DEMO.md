#  Demo
To run this program, you need a program (VM or bare-metal) which has the apt pkg manager. Developed on Ubuntu 20.04 and 22.04. _Ubuntu 20.04 required forced use of cgroups 2_. 

## Report Test Table (Expected)
*Note: Compiled binaries are not pushed into GH*.
There is no need to reset between sessions as each sandbox enviorment is unique.
| Source File Name | Compiled Name | Expected Behavior | Actual Result | Result |
| --- | --- | --- | --- | --- |
| networking.c | mal_net | _DNS lookup failed (blocked or no network)_ printed | DNS lookup failed (blocked or no network) | PASS |
| esc_fs.c | escape_fs | Program should be killed | ACT | IN-PROGRESS |
| exhaust_cpu.c | exh_cpu | Program should be killed | ACT | IN-PROGRESS |
| exhaust_mem.c | exh_mem | Program should be killed | ACT | IN-PROGRESS |
| set_uid_root.c | set_uid | Program should be killed | ACT | IN-PROGRESS |
| snoop_mem.c | snoop | Program should be killed | ACT | IN-PROGRESS |
