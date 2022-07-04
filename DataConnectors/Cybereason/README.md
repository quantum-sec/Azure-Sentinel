# Description

This log source uses logic app workflow with log analytics send data plugin. This cybereason connector pulls in data from malops using 2 apis `detection/inbox` and `detection/details`. For additional logs, you can modify the workflow with additional apis. For more information refer to https://nest.cybereason.com/documentation/api-documentation/all-versions/

## Prerequisites

1. Cybereason username, password and hostname.
2. Log analytics workspace ID and shared Key

## Deploy the Azure Function using ARM template

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FAzure%2FAzure-Sentinel%2Fmaster%2FDataConnectors%2FCybereason%2Fazuredeploy_connector_cybereason.json)

<!-- Link will work after being merged to master-->
