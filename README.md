# ConfigTrace

ConfigTrace checks how named secret references move through a small set of deployment files. It reads configuration names and references. It does not connect to Vault or print secret values.

## What it checks

1. An Ansible variable points to a named key in a Vault path.
2. A dotenv template maps that variable to an environment name.
3. A Compose service reads the same environment name.
4. A Kubernetes workload refers to a key declared by an ExternalSecret.

The example files use fictional names and contain no secret values.

## Run the example

Python 3.11 or newer is required.

```sh
pip install .
configtrace check examples/demo
```

A successful check prints:

```text
All declared references are connected.
```

Run the tests with:

```sh
python run_tests.py
```

## Try a broken reference

Change `api_password` in `examples/demo/deploy/app.env.j2` to another name, then run the check again. ConfigTrace reports that the template name has no matching Vault lookup.

## Project files

`configtrace.yml` lists the files to inspect. ConfigTrace checks a small, explicit set of common patterns so each result can be traced to a file and a key name.

## Limits

This is a static check. It does not contact Vault, Kubernetes, Docker, or Ansible. It does not verify permissions, runtime injection, or whether a secret value is valid. The first version supports a small set of YAML and template patterns.
