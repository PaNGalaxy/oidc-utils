# SSH OIDC
This repository is for developing a PAM module that authenticates users by using 
tokens instead of passwords, ssh keys, etc.

Using keyboard-interactive authentication, the PAM module asks the user to supply 
an OIDC token when they try to SSH into a machine where it is installed. 
Due to the long sizes that tokens can grow to, there are multiple prompts. 
Users should split their token into three parts to properly connect. 
Note: Users will rarely if ever have to directly interact with this PAM module,
so this shouldn't be something that they will have to do manually.

## Config
In order to properly set up the PAM module the `oidc-config.json` file needs to be set
with the proper configuration. This config is where you specify where logs should be 
written to, whether or not two-factor authentication is needed, and most importantly,
the JWKS URI of your OIDC provider. This URI will determine which tokens you can properly 
validate, so it is important to make sure that it is correct. `oidc-config-test.json` 
is also provided for testing purposes if one needs to mess with configuration without 
touching the actual config file. 

## Source Code
There are two versions of the PAM module in this repository, one written in C and the other
in Python. The Python version is handy if one wants to try out different implementations
quickly, but the C version is what should be used in any sort of production or real-world environment.
There are several Dockerfiles in the `dockerfiles/` directory that can be used to build each PAM module.
For example, in order to build the python version you could run 
`docker build -f dockerfiles/Dockerfile.python -t oidc-pam-python`. 
There is also a provided build script in the `c/` directory named `build.sh` that you 
can use to compile the C PAM module. 

## Testing
While there are no official unit tests at the moment, both PAM modules can be tested fairly easily.
For the C version, there is a provided main script `build/oidc-pam-main` built from `main.c`.
You can run this script like so: `./oidc-pam-main <path-to-config> <oidc-token>`. 
This is a good way to test changes fairly quickly. The Python PAM module doesn't have a provided 
script for testing, but you can write your own, import the Python script, and test the functions directly. 

It is also possible to try out the PAM modules via ssh-ing into them directly, 
but this is a little bit more involved. First, build your image as described above. 
Then run said image as a container using `docker run <image> --name <name-for-container>`. 
Then grab the IP address of your running container by executing: 
`docker inspect -f "{{ .NetworkSettings.IPAddress }}" <name-of-container>`. 
You can then run `ssh <ip-address-of-container>` and complete the prompts. 
If successful, you should authenticate into the container. However, if this fails, 
we can still check logs from the PAM module by directly connecting to the container.
We do this by running `docker exec -it <name-of-container> /bin/bash`. 
From here you can navigate to wherever your log file is (which, again, is specified in
the config file `oidc-config.json`), and see the logs from the PAM module. 