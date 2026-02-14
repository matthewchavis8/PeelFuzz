# TODO:
 Driver:
  - need to seperate the types from the actual wrappers
    have two different folders for types and wrappers also compiled into static libs
 Engine:
    - Need to increase the throughput 
    - also some way to enable tui
    - also the harness will not always be byte size could be a string or it could be registers this is why it has to be modular
      I should not have to be creating a new function for each harness everytime also the main componenets on LibAL needs to be swappable you knwo what i mean
      maybe we can place each type of scheduler into their own file or something then we can swap 
 - in order to run the user has to link both libdriver.a and libpeelfuzz.a be nice if they only have to link one static lib

  
    
