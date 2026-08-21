---
tags: ["Cybersecurity","Detection Engineering","Threat Hunting","SOAR","SIEM"]
Author: Javier Rollan
Date: 2025-10-22
---
# Third test this is a test with a longer title to make some tests {: .py-3 }

## This is the first Header {: .py-3 }

This is another test for the output quality of the markdown also I have now discovered how we can use the classes inside the markdown!

So this is a win win situation

## This is the second Header {: .py-3 }

Now we have tables too! or it should be like that

First column | Second Column
------------ | -------------
Content 1    | Content
This is cool! | This is even more coooler

More text to fill out the blog post

## This is the third Header {: .py-3 }

Now what is here? maybe another test for other things. For example a codeblock:

``` {: .yaml .border .rounded-bottom }
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

Fix?
