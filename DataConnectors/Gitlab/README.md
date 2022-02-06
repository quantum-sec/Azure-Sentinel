## Description
This log source uses logic app workflow with log analytics send data plugin. This GitLab connector uses 3 types of audit logs (Project Audit, Group Audit and user events). For additional audit logs, you can modify the workflow with additional APIs. For more information on GitLab audit events, refer to https://docs.gitlab.com/ee/api/audit_events.html

## Prerequisites
1. Gitlab personal access token with read permissions for groups and projects.
2. Gitlab Group ID and Project ID required for audit log ingestion.
3. Log analytics workspace ID and shared Key

## Logic APP Design
![LogicAppWorkflow](./LogicApp.png)<br>


## Deploy the Logic App template
[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/<Tobeadded>)

## Authorize API Connection
After deployment, go to `API Connections` to authorize for: 
1. Azure Keyvault by clicking on `Authorize button`.
![KVAPIConnection](./KVAPIConnection.png)<br>