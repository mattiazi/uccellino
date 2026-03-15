# uccellino

uccellino is a tool/automation layer for CrowdStrike Falcon, you can use it in your CI/CD pipelines or as a CLI.

> Why `uccellino` is named like that? Because it's the Italian word for "little bird", and Falcon is a bird, simple as that, not that much creative I know.

## Features

- [x] IOC management: create, list, delete
- [ ] Endpoint management
- [ ] Threat Intel
- [ ] CSPM

## Usage

### IOC management

```bash
# Create an IOC
uccellino ioc create --type "domain" --value "malicious.com" --action "detect" --severity "medium" --description "This is a test IOC" --tags "test,example" --platforms "windows,linux"

# List IOCs
uccellino ioc list

# Delete an IOC
uccellino ioc delete --id "ioc-id"
```
