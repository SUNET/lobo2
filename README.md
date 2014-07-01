
The Son of Lobber
=================

The lobo2 project is a simple bittorrent tracker and metadata repository with support for some form of external authentication infrastructure (eg federated identity).

There is also an OAUTH2-authenticated API. Possible use-cases include distribution of research datasets and library services. Unline its predecessor (the lobber codebase), lobo2 doesn't include any clent-side support, instead it is assumed that users will figure out how to integrate with the lobo2 API. 

Requirements
------------

- Python newer than 2.7 (not tested on python 3)
- Redis running on localhost
- For production you also need an http proxy that can do authentication and set REMOTE_USER

Install
-------

1. clone the repo
2. create a virtualenv based on requirements.txt 
3. modify/create config.py - minimally change SECRET.  For production use remove AUTH_TEST and modify BASE_URL.
4. in a directory one-level up from the cloned repo run 
```sh
# . /your/virtualenv/activate
# gunicorn --log-level debug lobo2:app`
```
4. point your browser to localhost:8000
5. profit!

API docs are at http://localhost:8000/docs/api
