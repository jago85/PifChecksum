# PifChecksum
## N64 bootcode checksum algorithm
This is the checksum algorithm from the N64 bootrom (PIFROM) reverse engineered in C.

The program can calculate the checksum for any N64 rom file. The seed must be given by the user.

The checksum is only applied to the first 4 kB of the ROM starting at offset 0x40.

Normally, seed and checksum are stored in the CIC inside of a N64 cartridge. The seed is given to the boot process. The code from the PIFROM executes on the N64 main processor. This algorithm calculates the checksum of the cartridge's bootcode. The result is given back to the PIF which compares the data to the value stored in the CIC. The PIF locks up the system if the two values don't match.

There are not so much combinations of different bootcodes and seeds out there. So every checksum should be already known. Maybe this algorithm is interesting for someone.

Example usage:
Running the program on any 6102 game (e.g. Mario64) and the seed 3f3f the output looks like this:

    ./PifChecksum sm64.v64 3f3f
    Checksum: 0xA536 C0F1D859

