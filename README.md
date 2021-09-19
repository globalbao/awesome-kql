# Azure Resource Graph KQL queries

Get in touch :octocat:

* Twitter: [@coder_au](https://twitter.com/coder_au)
* LinkedIn: [@JesseLoudon](https://www.linkedin.com/in/jesseloudon/)
* Web: [jloudon.com](https://jloudon.com)
* GitHub: [@JesseLoudon](https://github.com/jesseloudon)

## Azure Portal KQL
* [What is Azure Resource Graph?](https://docs.microsoft.com/en-us/azure/governance/resource-graph/overview)
* [Starter Resource Graph query samples](https://docs.microsoft.com/en-us/azure/governance/resource-graph/samples/starter?tabs=azure-cli)
* [Graph Query Language](https://docs.microsoft.com/en-us/azure/governance/resource-graph/concepts/query-language)
* [Kusto Overview](https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/)

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
| where tags !contains 'costcentre'
| project name, resourceGroup, subscriptionId, location, tags
| summarize count () by subscriptionId
```

#### Count `resource groups` missing the `application` tag
```kql
resourcecontainers
| where type == "microsoft.resources/subscriptions/resourcegroups"
| where tags !contains 'application'
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
| where type contains 'publicIPAddresses' and properties.ipAddress == "12.345.678.910"
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
| join kind=leftouter (ResourceContainers | where type=='microsoft.resources/subscriptions' | project SubcriptionName=name, subscriptionId) on subscriptionId
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
| project SubcriptionName, resourceGroup, subnet_name, name, rule_name, direction, priority, access, description, protocol, sourceport, sourceprefix, sourceApplicationSecurityGroups, destport, destprefix, destinationApplicationSecurityGroups
| sort by SubcriptionName, resourceGroup, name asc, direction asc, priority asc
```

## PowerShell KQL
* [Run your first Resource Graph query using Azure PowerShell](https://docs.microsoft.com/en-us/azure/governance/resource-graph/first-query-powershell)

### :star: AzGraph Queries w/ export to JSON

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

$resourceGroups = Search-AzGraph -Query "ResourceContainers | project-away resourceGroup,managedBy,tenantId,identity,zones,extendedLocation,sku,plan,properties,kind,type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\ResourceGroups.json

$virtualNetworks = Search-AzGraph -Query "Resources | where type == 'microsoft.network/virtualnetworks' | project-away managedBy,tenantId,identity,zones,extendedLocation,sku,plan,kind,type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\VirtualNetworks.json

$redis = Search-AzGraph -Query "Resources | where type == 'microsoft.cache/redis' | project-away managedBy,tenantId,identity,zones,extendedLocation,sku,plan,kind,type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\Redis.json

$availabilitySets = Search-AzGraph -Query "Resources | where type == 'microsoft.compute/availabilitysets' | project-away managedBy,tenantId,identity,zones,extendedLocation,sku,plan,kind,type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\AvailabilitySets.json

$disks = Search-AzGraph -Query "Resources | where type == 'microsoft.compute/disks' | project-away managedBy,tenantId,identity,zones,extendedLocation,plan,kind,type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\Disks.json

$virtualMachines = Search-AzGraph -Query "Resources | where type == 'microsoft.compute/virtualmachines' | project-away managedBy,tenantId,identity,zones,extendedLocation,plan,sku,kind,type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\VirtualMachines.json

$virtualMachinesExtensions = Search-AzGraph -Query "Resources | where type == 'microsoft.compute/virtualmachines/extensions' | project-away managedBy,tenantId,identity,zones,extendedLocation,plan,sku,kind,type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\VirtualMachinesExtensions.json

$virtualMachinesScaleSets = Search-AzGraph -Query "Resources | where type == 'microsoft.compute/virtualmachinescalesets' | project-away managedBy,tenantId,identity,zones,extendedLocation,plan,kind,type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\VirtualMachinesScaleSets.json

$managedClusters = Search-AzGraph -Query "Resources | where type == 'microsoft.containerservice/managedclusters' | project-away managedBy,tenantId,identity,zones,extendedLocation,plan,kind,type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\ManagedClusters.json

$dataFactories = Search-AzGraph -Query "Resources | where type == 'microsoft.datafactory/factories' | project-away managedBy,tenantId,identity,zones,extendedLocation,plan,sku,kind,type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\DataFactories.json

$appInsights = Search-AzGraph -Query "Resources | where type == 'microsoft.insights/components' | project-away managedBy,tenantId,identity,zones,extendedLocation,plan,sku,kind,type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\AppInsights.json

$keyVaults = Search-AzGraph -Query "Resources | where type == 'microsoft.keyvault/vaults' | project-away managedBy,tenantId,identity,zones,extendedLocation,plan,sku,kind,type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\KeyVaults.json

$applicationSecurityGroups = Search-AzGraph -Query "Resources | where type == 'microsoft.network/applicationsecuritygroups' | project-away managedBy,tenantId,identity,zones,extendedLocation,plan,sku,kind,type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\ApplicationSecurityGroups.json

$loadBalancers = Search-AzGraph -Query "Resources | where type == 'microsoft.network/loadbalancers' | project-away managedBy,tenantId,identity,zones,extendedLocation,plan,kind,type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\LoadBalancers.json

$networkInterfaces = Search-AzGraph -Query "Resources | where type == 'microsoft.network/networkinterfaces' | project-away managedBy,tenantId,identity,zones,extendedLocation,plan,sku,kind,type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\NetworkInterfaces.json

$publicIPAddresses = Search-AzGraph -Query "Resources | where type == 'microsoft.network/publicipaddresses' | project-away managedBy,tenantId,identity,zones,extendedLocation,plan,kind,type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\PublicIPAddresses.json

$searchServices = Search-AzGraph -Query "Resources | where type == 'microsoft.search/searchservices' | project-away managedBy,tenantId,identity,zones,extendedLocation,plan,kind,type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\SearchServices.json

$serviceBusNamespaces = Search-AzGraph -Query "Resources | where type == 'microsoft.servicebus/namespaces' | project-away managedBy,tenantId,identity,zones,extendedLocation,plan,kind,type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\ServiceBusNamespaces.json

$sqlManagedInstances = Search-AzGraph -Query "Resources | where type == 'microsoft.sql/managedinstances' | project-away managedBy,tenantId,zones,extendedLocation,plan,kind,type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\SqlManagedInstances.json

$storageAccounts = Search-AzGraph -Query "Resources | where type == 'microsoft.storage/storageaccounts' | project-away managedBy,tenantId,identity,zones,extendedLocation,plan,kind,type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\StorageAccounts.json

$webServerFarms = Search-AzGraph -Query "Resources | where type == 'microsoft.web/serverfarms' | project-away managedBy,tenantId,identity,zones,extendedLocation,plan,kind,type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\WebServerFarms.json

$webSites = Search-AzGraph -Query "Resources | where type == 'microsoft.web/sites' | project-away managedBy,tenantId,zones,extendedLocation,plan,kind,type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\WebSites.json

$notificationHubs = Search-AzGraph -Query "Resources | where type == 'microsoft.notificationhubs/namespaces/notificationhubs' or type == 'microsoft.notificationhubs/namespaces' | project-away managedBy,tenantId,zones,extendedLocation,plan,kind,type,subscriptionId" | ConvertTo-Json -Depth 100 | Out-File $FilePath\NotificationHubs.json
```