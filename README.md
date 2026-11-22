# Awesome KQL

Get in touch :octocat:

* Twitter: [@coder_au](https://twitter.com/coder_au)
* LinkedIn: [@JesseLoudon](https://www.linkedin.com/in/jesseloudon/)
* Web: [jloudon.com](https://jloudon.com)
* GitHub: [@JesseLoudon](https://github.com/jesseloudon)


# Azure Monitor KQL queries

### :star: Key Vault

#### Search for expiring Key Vault secrets and calculate Days till Expiry
Source: [Microsoft Learn: Azure Key Vault as an Event Grid source](https://learn.microsoft.com/en-us/azure/event-grid/event-schema-key-vault)

```kql
AzureDiagnostics
| where ResourceProvider == 'MICROSOFT.KEYVAULT'
| where OperationName == 'SecretNearExpiryEventGridNotification'
| extend SecretExpire = unixtime_seconds_todatetime(eventGridEventProperties_data_EXP_d)
| extend SecretName = eventGridEventProperties_data_ObjectName_s
| extend DaysTillExpire = datetime_diff("day", SecretExpire, now())
| project Resource,SecretName,DaysTillExpire
```

# Azure Resource Graph KQL queries

## Azure Portal KQL
* [What is Azure Resource Graph?](https://learn.microsoft.com/en-us/azure/governance/resource-graph/overview)
* [Starter Resource Graph query samples](https://learn.microsoft.com/en-us/azure/governance/resource-graph/samples/starter)
* [Graph Query Language](https://learn.microsoft.com/en-us/azure/governance/resource-graph/concepts/query-language)
* [Kusto Query Language reference](https://learn.microsoft.com/en-us/kusto/query/)

### :star: All Resources

#### Count `all resources` summarizing by `count` and ordering by `count`
```kql
Resources
| summarize count() by type 
| order by count_
```

### :star: Resource Groups

#### Count `resource groups` missing the `costcentre` tag
```kql
resourcecontainers
| where type == "microsoft.resources/subscriptions/resourcegroups"
| where isnull(tags['costcentre'])
| project name, resourceGroup, subscriptionId, location, tags
| summarize count () by subscriptionId
```

#### Count `resource groups` missing the `application` tag
```kql
resourcecontainers
| where type == "microsoft.resources/subscriptions/resourcegroups"
| where isnull(tags['application'])
| project name, resourceGroup, subscriptionId, location, tags
| summarize count () by subscriptionId
```

#### Query all tags for `resource groups` and `resources`
```kql
resourcecontainers
| where type == "microsoft.resources/subscriptions/resourcegroups"
| project  name,type,location,subscriptionId,tags
| union (resources | project name,type,location,subscriptionId,tags)
```

#### Query all tags for `resource groups` and `resources` and expand tag names/values to individual rows
```kql
resourcecontainers
| where type == "microsoft.resources/subscriptions/resourcegroups"
| mv-expand tags
| extend tagname = tostring(bag_keys(tags)[0])
| extend tagvalue = tostring(tags[tagname])
| project  name,id,type,location,subscriptionId,tagname,tagvalue
| union (resources 
| mv-expand tags
| extend tagname = tostring(bag_keys(tags)[0])
| extend tagvalue = tostring(tags[tagname])
| project name,id,type,location,subscriptionId,tagname,tagvalue)
```

## :star: Virtual Machines

### Query `virtual machines` and return `VM size`
```kql
Resources
| where type =~ 'Microsoft.Compute/virtualMachines'
| project vmName = name, vmSize=tostring(properties.hardwareProfile.vmSize), vmId = id
```

## :star: Public IP Addresses

### Query resources for a specific `publicIPAddress`
``` kql
Resources
| where type contains 'publicIPAddresses' and properties.ipAddress == "203.0.113.10"
```

### Count public IP addresses with an assigned IP by subscription
Source: [Microsoft Learn: Azure Resource Graph networking samples](https://learn.microsoft.com/en-us/azure/networking/resource-graph-samples)

```kql
Resources
| where type contains 'publicIPAddresses' and isnotempty(properties.ipAddress)
| summarize count() by subscriptionId
```

## :star: Load Balancers

### Query `load balancers` that are `Standard` SKU
``` kql
resources
| where type == "microsoft.network/loadbalancers" and sku.name == "Standard"
```

## :star: SQL Databases

### Query `sql databases` that do not contain the name `Master`
``` kql
resources
| where type == "microsoft.sql/servers/databases" and name notcontains "master"
```

## :star: ExpressRoute

### Query `virtual network gateways` that are `ExpressRoute` type
``` kql
resources
| where type == "microsoft.network/virtualnetworkgateways" and properties.gatewayType == "ExpressRoute"
```

### Query `network connections` that are `ExpressRoute` type
``` kql
resources
| where type == "microsoft.network/connections" and properties.connectionType == "ExpressRoute"
```

## :star: Web Server Farms / App Services

### Count `numberOfWorkers` for `web server farms`
```kql
resources
| where type == "microsoft.web/serverfarms"
| summarize count () by tostring(properties.numberOfWorkers)
```

### Query `web sites` that are not `functionapp`
```kql
resources
| where type == "microsoft.web/sites" and kind notcontains "functionapp"
```

## :star: Network Security Group Rules

### Query `network security groups` across all subscriptions expanding `securityRules`
```kql
Resources
| where type =~ "microsoft.network/networksecuritygroups"
| join kind=leftouter (ResourceContainers | where type=='microsoft.resources/subscriptions' | project SubscriptionName=name, subscriptionId) on subscriptionId
| mv-expand rules=properties.securityRules
| extend rule_name = tostring(rules.name)
| extend direction = tostring(rules.properties.direction)
| extend priority = toint(rules.properties.priority)
| extend access = rules.properties.access
| extend description = rules.properties.description
| extend protocol = rules.properties.protocol
| extend sourceprefix = rules.properties.sourceAddressPrefix
| extend sourceport = rules.properties.sourcePortRange
| extend sourceApplicationSecurityGroups = split((split(tostring(rules.properties.sourceApplicationSecurityGroups), '/'))[8], '"')[0]
| extend destprefix = rules.properties.destinationAddressPrefix
| extend destport = rules.properties.destinationPortRange
| extend destinationApplicationSecurityGroups = split((split(tostring(rules.properties.destinationApplicationSecurityGroups), '/'))[8], '"')[0]
| extend subnet_name = split((split(tostring(properties.subnets), '/'))[10], '"')[0]
| project SubscriptionName, resourceGroup, subnet_name, name, rule_name, direction, priority, access, description, protocol, sourceport, sourceprefix, sourceApplicationSecurityGroups, destport, destprefix, destinationApplicationSecurityGroups
| sort by SubscriptionName, resourceGroup, name asc, direction asc, priority asc
```

### Query network security groups that are not associated with a NIC or subnet
Source: [Microsoft Learn: Azure Resource Graph networking samples](https://learn.microsoft.com/en-us/azure/networking/resource-graph-samples)

```kql
Resources
| where type =~ 'microsoft.network/networksecuritygroups'
    and isnull(properties.networkInterfaces)
    and isnull(properties.subnets)
| project name, resourceGroup, subscriptionId
| sort by name asc
```

## :star: Storage Accounts

### Query storage accounts without HTTPS-only traffic enforcement
Source: [Microsoft/azure-skills: Azure Resource Graph compliance queries](https://github.com/microsoft/azure-skills/blob/main/skills/azure-compliance/references/azure-resource-graph.md)

```kql
Resources
| where type =~ 'microsoft.storage/storageaccounts'
| where properties.supportsHttpsTrafficOnly == false
| project name, resourceGroup, location
```

## :star: Virtual Machine Operating Systems

### Count virtual machines by operating system
Source: [Microsoft Learn: Starter Resource Graph query samples](https://learn.microsoft.com/en-us/azure/governance/resource-graph/samples/starter)

```kql
Resources
| where type =~ 'microsoft.compute/virtualmachines'
| summarize count() by tostring(properties.storageProfile.osDisk.osType)
```

## :star: Resource Group Locks

### Query resource groups without a directly scoped management lock
Source: [Microsoft/azure-skills: Azure Resource Graph compliance queries](https://github.com/microsoft/azure-skills/blob/main/skills/azure-compliance/references/azure-resource-graph.md)

```kql
ResourceContainers
| where type == 'microsoft.resources/subscriptions/resourcegroups'
| project rgName = name, rgId = id
| join kind=leftanti (
    Resources
    | where type == 'microsoft.authorization/locks'
    | project rgId = tostring(properties.resourceId)
) on rgId
```

## :star: Disks

### Query `microsoft.compute/disks`

```kql
resources
| where type == "microsoft.compute/disks"
| extend diskSizeGB = tostring(properties.diskSizeGB)
| extend timeCreated = tostring(properties.timeCreated)
| extend diskState = tostring(properties.diskState)
| project name,type,location,resourceGroup,diskState,diskSizeGB,timeCreated,managedBy
```

## :star: Security Assessments

### Query `microsoft.security/assessments` and show distinct values

```kql
securityresources
| where type == "microsoft.security/assessments"
| extend description = tostring(properties.metadata.description)
| extend displayName = tostring(properties.displayName)
| extend severity = tostring(properties.metadata.severity)
| extend remediationDescription = tostring(properties.metadata.remediationDescription)
| extend policyDefinitionId = tostring(properties.metadata.policyDefinitionId)
| extend implementationEffort = tostring(properties.metadata.implementationEffort)
| extend userImpact = tostring(properties.metadata.userImpact)
| distinct name, description, displayName, severity, remediationDescription, policyDefinitionId, implementationEffort, userImpact
```

## :star: Software Inventories

### Query `microsoft.security/softwareinventories` where there are known vulnerabilities

```kql
securityresources
| where type == 'microsoft.security/softwareinventories'
| extend numberOfKnownVulnerabilities = toint(properties.numberOfKnownVulnerabilities)
| extend softwareName = properties.softwareName
| extend softwareVersion = properties.version
| extend softwareVendor = properties.vendor
| extend virtualMachine = properties.azureVmId
| extend operatingSystem = properties.osPlatform
| where numberOfKnownVulnerabilities > 0
```


## :star: Azure Policy

### Query `policy states` filtering on `'NonCompliant'` results

```kql
policyresources
| where type == "microsoft.policyinsights/policystates"
| where properties.complianceState == 'NonCompliant'
| extend policyAssignmentParameters = todynamic(properties.policyAssignmentParameters),
policyDefinitionAction = tostring(properties.policyDefinitionAction),
policyAssignmentScope = tostring(properties.policyAssignmentScope),
policyAssignmentName = tostring(properties.policyAssignmentName),
policyDefinitionName = tostring(properties.policyDefinitionName),
policyDefinitionId = tostring(properties.policyDefinitionId),
 policyAssignmentId = tostring(properties.policyAssignmentId),
managementGroupIds = tostring(properties.managementGroupIds),
policyDefinitionReferenceId = tostring(properties.policyDefinitionReferenceId),
complianceState = tostring(properties.complianceState),
policySetDefinitionCategory = tostring(properties.policySetDefinitionCategory),
subscriptionId = tostring(properties.subscriptionId),
policySetDefinitionName = tostring(properties.policySetDefinitionName),
policySetDefinitionId = tostring(properties.policySetDefinitionId),
resourceType = tostring(properties.resourceType),
policyDefinitionGroupNames = todynamic(properties.policyDefinitionGroupNames),
stateWeight = toint(properties.stateWeight),
 resourceId = tostring(properties.resourceId),
isDeleted = tobool(properties.isDeleted),
timestamp = tostring(properties.timestamp)
| project timestamp,resourceId,resourceGroup,resourceType,complianceState,stateWeight,policyAssignmentName,policyAssignmentScope,policyAssignmentParameters,policySetDefinitionId,policySetDefinitionName,policySetDefinitionCategory,policyDefinitionId,policyDefinitionName,policyDefinitionAction,policyDefinitionReferenceId,policyDefinitionGroupNames,managementGroupIds,subscriptionId
```

### Query `Azure Security Benchmark` compliance across all subscriptions

```kql
// Regulatory compliance CSV report query for standard "Azure Security Benchmark" 
// Change the 'complianceStandardId' column condition to select a different standard
    securityresources
    | where type == "microsoft.security/regulatorycompliancestandards/regulatorycompliancecontrols/regulatorycomplianceassessments"
    | extend complianceStandardId = replace( "-", " ", extract(@'/regulatoryComplianceStandards/([^/]*)', 1, id))
    | where complianceStandardId ==  "Azure Security Benchmark"
    | extend failedResources = toint(properties.failedResources), passedResources = toint(properties.passedResources),skippedResources = toint(properties.skippedResources)
    | where failedResources + passedResources + skippedResources > 0 or properties.assessmentType == "MicrosoftManaged"
    | join kind = leftouter(
    securityresources
    | where type == "microsoft.security/assessments") on subscriptionId, name
    | extend complianceState = tostring(properties.state)
    | extend resourceSource = tolower(tostring(properties1.resourceDetails.Source))
    | extend recommendationId = iff(isnull(id1) or isempty(id1), id, id1)
    | extend resourceId = trim(' ', tolower(tostring(case(resourceSource =~ 'azure', properties1.resourceDetails.Id,
                                                        resourceSource =~ 'gcp', properties1.resourceDetails.GcpResourceId,
                                                        resourceSource =~ 'aws' and isnotempty(tostring(properties1.resourceDetails.ConnectorId)), properties1.resourceDetails.Id,
                                                        resourceSource =~ 'aws', properties1.resourceDetails.AwsResourceId,
                                                        extract('^(.+)/providers/Microsoft.Security/assessments/.+$',1,recommendationId)))))
    | extend regexResourceId = extract_all(@"/providers/[^/]+(?:/([^/]+)/[^/]+(?:/[^/]+/[^/]+)?)?/([^/]+)/([^/]+)$", resourceId)[0]
    | extend resourceType = iff(resourceSource =~ "aws" and isnotempty(tostring(properties1.resourceDetails.ConnectorId)), tostring(properties1.additionalData.ResourceType), iff(regexResourceId[1] != "", regexResourceId[1], iff(regexResourceId[0] != "", regexResourceId[0], "subscriptions")))
    | extend resourceName = tostring(regexResourceId[2])
    | extend recommendationName = name
    | extend recommendationDisplayName = tostring(iff(isnull(properties1.displayName) or isempty(properties1.displayName), properties.description, properties1.displayName))
    | extend description = tostring(properties1.metadata.description)
    | extend remediationSteps = tostring(properties1.metadata.remediationDescription)
    | extend severity = tostring(properties1.metadata.severity)
    | extend azurePortalRecommendationLink = tostring(properties1.links.azurePortal)
    | extend complianceStandardId = replace( "-", " ", extract(@'/regulatoryComplianceStandards/([^/]*)', 1, id))
    | extend complianceControlId = extract(@"/regulatoryComplianceControls/([^/]*)", 1, id)
    | mvexpand statusPerInitiative = properties1.statusPerInitiative
                | extend expectedInitiative = statusPerInitiative.policyInitiativeName =~ "ASC Default"
                | summarize arg_max(expectedInitiative, *) by complianceControlId, recommendationId
                | extend state = iff(expectedInitiative, tolower(statusPerInitiative.assessmentStatus.code), tolower(properties1.status.code))
                | extend notApplicableReason = iff(expectedInitiative, tostring(statusPerInitiative.assessmentStatus.cause), tostring(properties1.status.cause))
                | project-away expectedInitiative
    | project complianceStandardId, complianceControlId, complianceState, subscriptionId, resourceGroup = resourceGroup1 ,resourceType, resourceName, resourceId, recommendationId, recommendationName, recommendationDisplayName, description, remediationSteps, severity, state, notApplicableReason, azurePortalRecommendationLink
    | join kind = leftouter (securityresources
    | where type == "microsoft.security/regulatorycompliancestandards/regulatorycompliancecontrols"
    | extend complianceStandardId = replace( "-", " ", extract(@'/regulatoryComplianceStandards/([^/]*)', 1, id))
    | where complianceStandardId == "Azure Security Benchmark"
    | extend  controlName = tostring(properties.description)
    | project controlId = name, controlName
    | distinct  *) on $right.controlId == $left.complianceControlId
    | project-away controlId
    | distinct *
    | order by complianceControlId asc, recommendationId asc
```

## PowerShell KQL
* [Run your first Resource Graph query using Azure PowerShell](https://docs.microsoft.com/en-us/azure/governance/resource-graph/first-query-powershell)

### :star: AzGraph Queries w/ export to JSON

**Current Scope:**
* resource groups
* virtual networks
* redis cache
* availability sets
* disks
* virtual machines
* virtual machine extensions
* virtual machine scale sets
* managed clusters
* data factories
* key vaults
* application security groups
* load balancers
* network interfaces
* public IP addresses
* search services
* service bus namespaces
* sql managed instances
* storage accounts
* web server farms
* websites
* notification hubs

```powershell
# Install the Resource Graph module from PowerShell Gallery
Install-Module -Name Az.ResourceGraph

# Set a local File Path for JSON export
$FilePath = "C:\Temp\"

# Query resources, project away columns, and convert/export to JSON
$resourceGroups = Search-AzGraph -Query "ResourceContainers | project-away resourceGroup,managedBy,tenantId,identity,zones,extendedLocation,sku,plan,properties,['kind'],type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\ResourceGroups.json

$virtualNetworks = Search-AzGraph -Query "Resources | where type == 'microsoft.network/virtualnetworks' | project-away managedBy,tenantId,identity,zones,extendedLocation,sku,plan,['kind'],type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\VirtualNetworks.json

$redis = Search-AzGraph -Query "Resources | where type == 'microsoft.cache/redis' | project-away managedBy,tenantId,identity,zones,extendedLocation,sku,plan,['kind'],type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\Redis.json

$availabilitySets = Search-AzGraph -Query "Resources | where type == 'microsoft.compute/availabilitysets' | project-away managedBy,tenantId,identity,zones,extendedLocation,sku,plan,['kind'],type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\AvailabilitySets.json

$disks = Search-AzGraph -Query "Resources | where type == 'microsoft.compute/disks' | project-away managedBy,tenantId,identity,zones,extendedLocation,plan,['kind'],type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\Disks.json

$virtualMachines = Search-AzGraph -Query "Resources | where type == 'microsoft.compute/virtualmachines' | project-away managedBy,tenantId,identity,zones,extendedLocation,plan,sku,['kind'],type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\VirtualMachines.json

$virtualMachinesExtensions = Search-AzGraph -Query "Resources | where type == 'microsoft.compute/virtualmachines/extensions' | project-away managedBy,tenantId,identity,zones,extendedLocation,plan,sku,['kind'],type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\VirtualMachinesExtensions.json

$virtualMachinesScaleSets = Search-AzGraph -Query "Resources | where type == 'microsoft.compute/virtualmachinescalesets' | project-away managedBy,tenantId,identity,zones,extendedLocation,plan,['kind'],type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\VirtualMachinesScaleSets.json

$managedClusters = Search-AzGraph -Query "Resources | where type == 'microsoft.containerservice/managedclusters' | project-away managedBy,tenantId,identity,zones,extendedLocation,plan,['kind'],type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\ManagedClusters.json

$dataFactories = Search-AzGraph -Query "Resources | where type == 'microsoft.datafactory/factories' | project-away managedBy,tenantId,identity,zones,extendedLocation,plan,sku,['kind'],type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\DataFactories.json

$appInsights = Search-AzGraph -Query "Resources | where type == 'microsoft.insights/components' | project-away managedBy,tenantId,identity,zones,extendedLocation,plan,sku,['kind'],type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\AppInsights.json

$keyVaults = Search-AzGraph -Query "Resources | where type == 'microsoft.keyvault/vaults' | project-away managedBy,tenantId,identity,zones,extendedLocation,plan,sku,['kind'],type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\KeyVaults.json

$applicationSecurityGroups = Search-AzGraph -Query "Resources | where type == 'microsoft.network/applicationsecuritygroups' | project-away managedBy,tenantId,identity,zones,extendedLocation,plan,sku,['kind'],type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\ApplicationSecurityGroups.json

$loadBalancers = Search-AzGraph -Query "Resources | where type == 'microsoft.network/loadbalancers' | project-away managedBy,tenantId,identity,zones,extendedLocation,plan,['kind'],type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\LoadBalancers.json

$networkInterfaces = Search-AzGraph -Query "Resources | where type == 'microsoft.network/networkinterfaces' | project-away managedBy,tenantId,identity,zones,extendedLocation,plan,sku,['kind'],type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\NetworkInterfaces.json

$publicIPAddresses = Search-AzGraph -Query "Resources | where type == 'microsoft.network/publicipaddresses' | project-away managedBy,tenantId,identity,zones,extendedLocation,plan,['kind'],type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\PublicIPAddresses.json

$searchServices = Search-AzGraph -Query "Resources | where type == 'microsoft.search/searchservices' | project-away managedBy,tenantId,identity,zones,extendedLocation,plan,['kind'],type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\SearchServices.json

$serviceBusNamespaces = Search-AzGraph -Query "Resources | where type == 'microsoft.servicebus/namespaces' | project-away managedBy,tenantId,identity,zones,extendedLocation,plan,['kind'],type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\ServiceBusNamespaces.json

$sqlManagedInstances = Search-AzGraph -Query "Resources | where type == 'microsoft.sql/managedinstances' | project-away managedBy,tenantId,zones,extendedLocation,plan,['kind'],type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\SqlManagedInstances.json

$storageAccounts = Search-AzGraph -Query "Resources | where type == 'microsoft.storage/storageaccounts' | project-away managedBy,tenantId,identity,zones,extendedLocation,plan,['kind'],type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\StorageAccounts.json

$webServerFarms = Search-AzGraph -Query "Resources | where type == 'microsoft.web/serverfarms' | project-away managedBy,tenantId,identity,zones,extendedLocation,plan,['kind'],type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\WebServerFarms.json

$webSites = Search-AzGraph -Query "Resources | where type == 'microsoft.web/sites' | project-away managedBy,tenantId,zones,extendedLocation,plan,['kind'],type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\WebSites.json

$notificationHubs = Search-AzGraph -Query "Resources | where type == 'microsoft.notificationhubs/namespaces/notificationhubs' or type == 'microsoft.notificationhubs/namespaces' | project-away managedBy,tenantId,zones,extendedLocation,plan,['kind'],type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\NotificationHubs.json
```
