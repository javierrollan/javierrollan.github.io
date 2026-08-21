---
tags: ["Cybersecurity","Detection Engineering","Threat Hunting","SOAR","SIEM"]
Author: Javier Rollan
---

## The cooler threat modeling {: .py-3 }

Cybersecurity doesnt wait for anyone, 


## Effective detection engineering {: .py-3 }


## This is the third Header {: .py-3 }

Now what is here? maybe another test for other things. For example a codeblock:

<div class="card">
<div class="card-header font-monospace">
YAML
</div>
<div class="card-body p-0 m-0">

```yaml
- rule: ls_in_container
  desc: ls activity in container
  condition: >
    evt.type = execve and
    evt.dir = < and
    container.id != host and
    proc.name = ls
  output: >
    [direction <] ls in a container |
    user=%user.name container_id=%container.id container_name=%container.name
    proc_name=%proc.name parent=%proc.pname cmdline=%proc.cmdline evt_res=%evt.res
  priority: WARNING
  tags: [custom, test]
  enabled: false
```

</div>
</div>
