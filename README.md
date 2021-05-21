![](https://github.com/Secure-Compliance-Solutions-LLC/Hardening/raw/main/HardeningTools.png)

> #### :white_check_mark: below are clickable

### Linux

| Standard/Framework                | Linux Debian-Based | Linux Redhat-Based |Amazon Linux        |
| --------------------------------- | ------------------ | ------------------ | ------------------ |
| NIST Low (SP 800-53)           |                    |                    |                    |
| NIST Medium (SP 800-53)        |                    |                    |                    |
| NIST High (SP 800-53)          |                    |                    |                    |
| Center of Internet Security (CIS) |[:white_check_mark:](/Compliance-Linux/CIS)|[:white_check_mark:](/Compliance-Linux/CIS)|[:white_check_mark:](/Compliance-Linux/CIS)|
| HITRUST Level 1                   |                    |                    |                    |
| HITRUST Level 2                   |                    |                    |                    |
| HITRUST Level 3                   |                    |                    |                    |
|Secure Compliance Solutions Script |                    |                    |                    |



### Windows

| Standard/Framework                | Windows 10 | Windows Server 2016 | Windows Server 2019 |
| --------------------------------- | ---------- | ------------------- | ------------------- |
| NIST Low (SP 800-53)           |            |                     |                     |
| NIST Medium (SP 800-53)        |            |                     |                     |
| NIST High (SP 800-53)          |            |                     |                     |
| Center of Internet Security (CIS) |[:white_check_mark:](/Compliance-Windows/CIS)|[:white_check_mark:](/Compliance-Windows/CIS)|[:white_check_mark:](/Compliance-Windows/CIS)|
| HITRUST Level 1                   |            |                     |                     |
| HITRUST Level 2                   |            |                     |                     |
| HITRUST Level 3                   |            |                     |                     |
|Secure Compliance Solutions Script |            |                     |                     |




## Add to Third Parties

```
$ git submodule add <remote_url> Third-Parties
```

When adding a Git submodule, your submodule will be staged. As a consequence, you will need to commit your submodule by using the “git commit” command.

````
$ git commit -m "Added the submodule to the project."
$ git push
````



