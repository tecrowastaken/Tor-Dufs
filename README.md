# Tor-Dufs

A Fork around the dufs file server tool for running over tor.


## How To Compile Yourself
1. Download rust.

2. Run this command a file named tdufs.exe should be made
```
cargo build --release
```

3. For those who are too lazy to dig up the documentation for dufs
run this command.

```
tdufs --help
```

## Why Tor-Dufs
When it comes to exchanging confedential information. There should be a more secure way of Transfering files without the blunder of second-guessing or downloading multiple configuration files.

- This is an alternative to Onionshare if you want to keep the same hostname for your hidden service. This can be a benefit to some capacity if you generated a good vanity url to use, A Second benefit might be allowing people to edit, change and download files
all at one time.

- The closet you might get to an FTP Server would be this. FTP Protocols currently don't work over tor.

- When Collaberating on a project with groups of trusted anonymous people.

- When setting up php could be a mouthful. Better yet, assets are built-in.


## When Will We Be Migrating to Arti?

Were planning to migrate to using arti when all these conditions have been met...

- It can downloaded in a tor-developer-bundle or when a python
  is fully supported by arti. 
  
- If Arti can be quick and dirty and you are able to make temporary config files using it. Without screwing with the main config file.

- When Arti can be statically compiled to an exe. I have a personal hate for tracking down and downloading dlls.

- When Compiling Arti becomes a safer habit. (Windows is finally fully supported and I don't have to hunt down and sneak in eviornment variables to make it all work...)
  
- Arti makes the use of socket listeners optional, I prefer port-forwarding the old fashioned way thank you very much...

## When can we have precompiled binary releases?
When I manage to make a workflow that works or when I have time to figure out why my other projects won't compile.

## Will this be added to Dufs?
Hope so but I had the idea of keeping these features seperate to prevent controversy or if this concept is rejected.

## Documentation
- [See The Repo I forked](https://github.com/sigoden/dufs)

## Tips
- Try not to use the default directory when hosting a folder because making the default hidden-service directory be hidden has not been implemented and getting this wrong can lead to an attacker finding the key of your hidden service which is bad.

- If your on windows set tor.exe as a path enviornment variable to your tor.exe file. It should be done the same way you would install python and make the python command global.

