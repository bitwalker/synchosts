# synchosts.py

This simple script will update /etc/hosts entries that contain *.local or local.* hostnames
by pulling the IP address of a specified VM host.

## Why?

If you are a Windows dev hosting your dev environment in Parallels while working in OSX, then
you likely host applications in IIS on your host and work from OSX. In order for this setup to
work, you probably also have been manually updating /etc/hosts periodically when your VM's IP
changes. Why do this by hand when you can do it automagically!

## How it works

This script uses the Parallels SDK to query the local VM library for the specified VM, accesses
it's list of adapters, and extracts an IPv4 address from the adapter's current network information.
That IP is then used to generate a new hosts file where all *.local and local.* host entries point
to the new IP address. It then uses `sudo mv` to overwrite the current hosts file, which requires
you to provide your credentials.

## Changes

If you have a creative way of making this work better, spotted a bug or three, or just want to expand
it's capabilities, fork and shoot me a pull request. Thanks!

## License

This is released under my super special "I really could care less what you do with this" license.
