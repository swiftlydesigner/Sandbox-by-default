#  Demo
To run this program, you need a program (VM or bare-metal) which has the apt pkg manager. Developed on Ubuntu 20.04 and 22.04. _Ubuntu 20.04 required forced use of cgroups 2_. 

## Report Test Table (Expected)
*Note: Compiled binaries are not pushed into GH*.
There is no need to reset between sessions as each sandbox enviorment is unique.
| Source File Name | Compiled Name | Expected Behavior | Actual Result | Result |
| --- | --- | --- | --- | --- |
| networking.c | mal_net | _DNS lookup failed (blocked or no network)_ printed | DNS lookup failed (blocked or no network) | PASS |
| esc_fs.c | escape_fs | Program should be killed | Killed! | PASS |
| exhaust_cpu.c | exh_cpu | Program should be killed | Killed! | PASS |
| exhaust_mem.c | exh_mem | Program should be killed | Killed! | PASS |
| set_uid_root.c | set_uid | Program should be killed | Killed! | PASS |
| snoop_mem.c | snoop | Program should be killed | Killed! | PASS |

## Running a local demo
- Download Ubuntu 20.04, upto 22.04. 26.xx is know to have issues with cgroups
- clone project and run `bash run.sh` wait for code to compile and results will be printed on display

## Findings/current standing (lower = more updated)
- Networking works on own with other setup code commented out
- user namespace config is not having sufficent premissions. Fails at `write_file("/proc/self/setgroups", "deny\n") == -1` in `namespace/user_namespace.c`
- Seccomp on its own handled all tests. 
