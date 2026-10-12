# Workload draft

`vpscfg fleet translate` reads one compose file or one Deployment and prints a
draft. It does not apply, write a contract, or open a network connection.

```text
vpscfg fleet translate compose-to-k3s PATH --service NAME
vpscfg fleet translate k3s-to-compose PATH --container NAME
```

`--run` and `--output` are refused. The draft is JSON on stdout. `executable`
and `applied` are false. `limits.nodes_observed` is null; the draft does not
claim the cluster is single-node. Exit 0 means the draft has no refusal. Exit 1
means the draft is blocked. Exit 2 means the input itself was refused. Input is
refused above 1 MiB, past 64 levels of nesting, or past 100,000 visited nodes.
YAML anchors are allowed, and each alias use counts toward that node limit.

Refusals cover volumes, secrets, secret-like environment names, host
networking, privileged mode, privilege expansion, a frozen namespace, and
`imagePullPolicy: Always`. Environment values, commands, arguments, image tags,
and digests are not copied. A service name that is not a Kubernetes name is
refused and is not rewritten.

The draft is not a contract. It is missing host, repo, verify, and scope. The
first real use waits for a named disposable service on the stage-2 test host,
after rollback of that host has been proven.
