# Azure Resource Graph KQL queries
* [What is Azure Resource Graph?](https://docs.microsoft.com/en-us/azure/governance/resource-graph/overview)
* [Starter Resource Graph query samples](https://docs.microsoft.com/en-us/azure/governance/resource-graph/samples/starter?tabs=azure-cli)
* [Graph Query Language](https://docs.microsoft.com/en-us/azure/governance/resource-graph/concepts/query-language)
* [Kusto Overview](https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/)


### Count `all resources` summarizing by `count` and ordering by `count`
```kql
Resources
| summarize count() by type 
| order by count_
```

### Count `resource groups` missing the `costcentre` tag
```kql
resourcecontainers
| where type == "microsoft.resources/subscriptions/resourcegroups"
| where tags !contains 'costcentre'
| project name, resourceGroup, subscriptionId, location, tags
| summarize count () by subscriptionId
```

### Count `resource groups` missing the `application` tag
```kql
resourcecontainers
| where type == "microsoft.resources/subscriptions/resourcegroups"
| where tags !contains 'application'
| project name, resourceGroup, subscriptionId, location, tags
| summarize count () by subscriptionId
```

### Query all tags for `resource groups` and `resources`
```kql
resourcecontainers
| where type == "microsoft.resources/subscriptions/resourcegroups"
| project  name,type,location,subscriptionId,tags
| union (resources | project name,type,location,subscriptionId,tags)
```

### Query resources for a specific `publicIPAddress`
``` kql
Resources
| where type contains 'publicIPAddresses' and properties.ipAddress == "12.345.678.910"
```

### Query `load balancers` that are `Standard` SKU
``` kql
resources
| where type == "microsoft.network/loadbalancers" and sku.name == "Standard"
```

### Query `sql databases` that do not contain the name `Master`
``` kql
resources
| where type == "microsoft.sql/servers/databases" and name notcontains "master"
```

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

### Query `network security groups` expanding `securityRules`
```kql
Resources
| where type =~ "microsoft.network/networksecuritygroups"
| join kind=leftouter (ResourceContainers | where type=='microsoft.resources/subscriptions' | project SubcriptionName=name, subscriptionId) on subscriptionId
| mv-expand rules=properties.securityRules
| extend direction = tostring(rules.properties.direction)
| extend priority = toint(rules.properties.priority)
| extend access = rules.properties.access
| extend description = rules.properties.description
| extend destprefix = rules.properties.destinationAddressPrefix
| extend destport = rules.properties.destinationPortRange
| extend sourceprefix = rules.properties.sourceAddressPrefix
| extend sourceport = rules.properties.sourcePortRange
| extend subnet_name = split((split(tostring(properties.subnets), '/'))[10], '"')[0]
| project SubcriptionName, resourceGroup, subnet_name, name, direction, access, priority, sourceport, sourceprefix, destport, destprefix, description
| sort by SubcriptionName, resourceGroup asc, name, direction asc, priority asc
```
