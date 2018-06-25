# PIvirus

PIvirus is a proof of concept for infecting linux x86_64 ELF binaries using PLT redirection technique

## How it works

- the virus looks for **fclose** function and hijacks it with a function that writes garbage from the stack to the stdout 

- the virus will infect x86_64 ELF binaries with the type **[ ET_DYN || ET_EXEC ]**

- parasite injection is done by extending the text segment

- PLT redirection happens at runtime and the virus is able to handle binaries which does not apply lazy binding

## Usage

```  #./pivirus [ target directory ] ```

<p align="center">
  <img alt="PIvirus-demo" src ="https://media.giphy.com/media/5WJe29jCGuVHrjJI0W/giphy.gif"/>
</p>

## License

MIT
