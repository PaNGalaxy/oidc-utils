# OIDC-based Authentication

This project enables user authentication on servers using OpenID Connect tokens. It includes a PAM module for SSH login
via an OIDC token and a utility for executing commands and copying files on behalf of a user, also utilizing an OIDC
token for authentication.

## The PAM Module

The PAM module utilizes keyboard-interactive authentication, prompting the user to supply an OIDC token when attempting
to SSH into a machine with the module installed. Since tokens can grow large and potentially exceed
the `PAM_MAX_RESP_SIZE` value, multiple prompts are provided. Users should split their tokens into multiple parts for
proper connection.

Note: Users will rarely, if ever, need to directly interact with this PAM module, as it's typically automated.
But an [example script](examples/ssh_connect.py) demonstrates how this can be handled.

## Run-as-User Utility

This utility allows the execution of commands on behalf of a user. It verifies the user token, extracts the username
from it, searches for the corresponding `uid`, and switches to it before executing the command. The utility needs to
have `setuid` set to be able to do that.

## Configuration

### Configuration File

To properly configure the PAM module and utility, the `oidc-config.json` file must be set up with the correct
parameters. See the [oidc-pam.json](config/oidc-pam.json) example.

### SSH/PAM Configuration

For the PAM module, SSH server and PAM configuration must be properly configured. Refer
to [sshd.conf](config/sshd_pam.conf) for SSH configuration and [sshd](config/sshd) for PAM configuration.

## Building

You can build locally using `CMake` or within Docker containers. Refer to the corresponding Docker files
for [Ubuntu](dockerfiles/Dockerfile.ubuntu) and [openSUSE](dockerfiles/Dockerfile.opensuse). Both RPM and DEB packages
are built within these images. GitLab CI/CD pipelines are utilized for package generation, but manual generation is also
possible.

## Testing

Both the utility and PAM modules can be tested easily. First, prepare a config file with OIDC provider information. See
the [oidc-pam.json](config/oidc-pam.json) example.

For PAM testing, run one of the provided containers (mounting the config file to `/tmp/oidc/oidc-pam.json`) and attempt
SSH login using the provided [example script](examples/ssh_connect.py).
You cannot directly copy/paste token due to the size limitations described above.

For the `run_as_user` utility, simply execute the binary file with the necessary parameters.
