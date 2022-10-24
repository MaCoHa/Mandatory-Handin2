### Security 1, BSc 2022 -- Mandatory Hand-in 2
Hand-in Date: 25 October  2022 (at 23:59)

# Requerements 
Have go installed and can call "go run"
Have port 8085 open. 

if the port is not available.
Change the port number in Bob/main.go line 22 and Alice/main.go line 27 to a port that is available.

# How to run 
## Starting Bob
  First you need to a terminal in the root folder.. Then run the following command in the terminal
  ```golang
  // Starting Bob / the server
  go run Bob/main.go 
 ```
 Bob will print "server listening at 127.0.0.1:8085" when he is done setting up
## Starting Alice
Then when Bob is running open a new terminal in the root folder. Then run the following command in the terminal.
```golang
// Starting Alice / the Client
  go run Alice/main.go 0
  ```
  When Alice starts she approaches bob so they can exchange public keys in a dark ally. 
  ## Once Both Alice and Bob are running

once that's done they are ready to play dice. The terminal running Alice will be awaiting any input from you. Each time any input is given she and bob will throw a die and both print each of their results. then Alice will be awaiting a new input