# iRODS Protocol Cookbook

This repository demonstrates key operations in the iRODS protocol. It shows protocol messages being
constructed as strings and sent over a TCP socket. This is intended to serve as a starting point
for writing client libraries and applications.

## Setup

You will need to install Jupyter to run the notebook. You also need an 
installation of the data processing library Pandas, and if you're 
using a virtual environment (which you should be), you also need to 
let the iPython kernel know about it. 

- [Jupyter installation instructions](https://jupyter.org/install)
- [More Jupyter installation docs](https://jupyter-notebook-beginner-guide.readthedocs.io/en/latest/install.html#)
- [Creating a virtulenv for Python](https://docs.python.org/3/library/venv.html)
- [Configuring ipykernel for virtual environments](https://ipython.readthedocs.io/en/latest/install/kernel_install.html#kernel-install)

## iRODS

This notebook can be run without any local iRODS installation. The only requirement is the hostname of a 
valid iRODS Catalog Provider. This could be a deployed iRODS installation, or a containerized iRODS test zone.
The fastest way of standing up such an instance is by cloning the [iRODS Testing Environment repository](https://github.com/irods/irods_testing_environment)
and running something like the following script while in that repo's root directory:

```bash
python stand_it_up.py \
    --irods-package-directory path/to/packages\
    --project-directory path/to/project-dir
```

Further instructions can be found in the introduction of the Notebook itself.
