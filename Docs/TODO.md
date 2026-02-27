# TODO:
 Engine:
 - no_std must have:
   - crash handling print register state to see what caused the crash is not a bad move
     - For this one how I did it before is that I had this buffer and a jmp table to restart the process.
       The meta was that when the engine passses the buffer to the target there is something that will catch it. This crash handler would dump the crash input before contiuing to fuzz. It can recover using a jmp table and fuzz forever pretty much
   - somehow incorporate some sort of enthrophy so the fuzzer will not be deterministic
   - crash recovery

CRITIQUES:
 - 
