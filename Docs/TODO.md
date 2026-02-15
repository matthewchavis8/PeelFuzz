# TODO:
 Docs: (DO not do for now)
   - Need to document the Engine defintely needs its own readme right there
   - need to rework documentation
   - Update documentation with the current calls for the fuzzer look at the example make file to see how
   - add plant UML and flow charts
 Engine:
    - Command line for enabling the features like default, fork, etc for the Engine side
       by default we should just take advantage of multicore fuzzing always not sure why we are explicilty have to call fork 
       only if we have to we fall to single core not sure why we are splitting modes here. The split will come in the future when 
       we add baremetal support but we can worry about that later
    - update docs to how to build and run right now I only know how to build the driver feels like instrucitons are not clear
