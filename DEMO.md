#  Demo
To run this program, you need a program (VM or bare-metal) which has the apt pkg manager. Developed on Ubuntu 20.04 and 22.04. _Ubuntu 20.04 required forced use of cgroups 2_. 

## Report Test Table (Expected)
*Note: Compiled binaries are not pushed into GH*.
There is no need to reset between sessions as each sandbox enviorment is unique.
| Source File Name | Compiled Name | Expected Behavior | Actual Result |
| --- | --- | --- | --- |
| networking.c |  mal\_net| _Network access BLOCKED - connection failed as expected_ printed | <Unavailable> |
|  |  |  |  |
