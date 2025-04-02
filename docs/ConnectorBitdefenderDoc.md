## About the connector
Bitdefender Endpoint Detection and Response (EDR) is a security solution designed to detect, investigate, and respond to advanced cyber threats on endpoints. This connector enables automated operations such as Get Computers Quarantine List, Get Exchange Quarantine List, and others.
<p>This document provides information about the Bitdefender Connector, which facilitates automated interactions, with a Bitdefender server using FortiSOAR&trade; playbooks. Add the Bitdefender Connector as a step in FortiSOAR&trade; playbooks and perform automated operations with Bitdefender.</p>

### Version information

Connector Version: 1.0.0


Authored By: Fortinet SE

Certified: No
## Installing the connector
<p>Use the <strong>Content Hub</strong> to install the connector. For the detailed procedure to install a connector, click <a href="https://docs.fortinet.com/document/fortisoar/0.0.0/installing-a-connector/1/installing-a-connector" target="_top">here</a>.</p><p>You can also use the <code>yum</code> command as a root user to install the connector:</p>
<pre>yum install cyops-connector-bitdefender</pre>

## Prerequisites to configuring the connector
- You must have the credentials of Bitdefender server to which you will connect and perform automated operations.
- The FortiSOAR&trade; server should have outbound connectivity to port 443 on the Bitdefender server.

## Minimum Permissions Required
- Not applicable

## Configuring the connector
For the procedure to configure a connector, click [here](https://docs.fortinet.com/document/fortisoar/0.0.0/configuring-a-connector/1/configuring-a-connector)
### Configuration parameters
<p>In FortiSOAR&trade;, on the Connectors page, click the <strong>Bitdefender</strong> connector row (if you are in the <strong>Grid</strong> view on the Connectors page) and in the <strong>Configurations</strong> tab enter the required configuration details:</p>
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Server URL</td><td>Specify the server URL to connect and perform automated operations.
</td>
</tr><tr><td>API Token</td><td>Specify the API token.
</td>
</tr><tr><td>Company ID</td><td>Specify the company ID.
</td>
</tr><tr><td>Verify SSL</td><td>Specifies whether the SSL certificate for the server is to be verified or not. <br/>By default, this option is set to True.</td></tr>
</tbody></table>

## Actions supported by the connector
The following automated operations can be included in playbooks and you can also use the annotations to access operations from FortiSOAR&trade; release 4.10.0 and onwards:
<table border=1><thead><tr><th>Function</th><th>Description</th><th>Annotation and Category</th></tr></thead><tbody><tr><td>Get Computers Quarantine List</td><td>This method retrieves the list of quarantined items available for a company.</td><td>get_computers_quarantine_items_list <br/>Investigation</td></tr>
<tr><td>Get Exchange Quarantine List</td><td>This method retrieves the exchange quarantined items available for a company.</td><td>get_exchange_quarantine_items_list <br/>Investigation</td></tr>
<tr><td>Get Accounts List</td><td>Retrieves all the user accounts that belong to a company.</td><td>get_accounts_list <br/>Investigation</td></tr>
<tr><td>Get Policies List</td><td>This method retrieves the list of available policies.</td><td>get_policies_list <br/>Investigation</td></tr>
<tr><td>Add to Blocklist</td><td>Adds items (hashes, paths, or connection rules) to the Bitdefender blocklist.</td><td>add_to_blocklist <br/>Security</td></tr>
<tr><td>Get Block List Items</td><td>This method lists all the hashes that are present in a blocklist.</td><td>get_block_list_items <br/>Security</td></tr>
<tr><td>Remove from BlockList</td><td>This method removes an item from the Blocklist, identified by its ID.</td><td>remove_from_blocklist <br/>Security</td></tr>
<tr><td>Create Isolate Endpoint Task</td><td>This method creates a task to isolate the specified endpoint.</td><td>create_isolate_endpointtask <br/>Security</td></tr>
<tr><td>Create Restore Endpoint from Isolation</td><td>This method creates a task to restore the specified endpoint from isolation.</td><td>createRestoreEndpointFromIsolationTask <br/>Security</td></tr>
<tr><td>Get Custom Rules List</td><td>This method retrieves the custom rules list for a specific company.</td><td>get_custom_rule_list <br/>Security</td></tr>
<tr><td>Delete Custom Rule</td><td>Deletes a custom rule.</td><td>delete_custom_rule <br/>Security</td></tr>
<tr><td>Update Incident Note</td><td>This method assigns a note to an incident.</td><td>update_incident_note <br/>Security</td></tr>
<tr><td>Change Incident Status</td><td>This method changes the status of an incident.</td><td>change_incident_status <br/>Security</td></tr>
<tr><td>Get Endpoints List</td><td>This method returns the list of endpoints.</td><td>get_endpoints_list <br/>Security</td></tr>
<tr><td>Get Managed Endpoints Details</td><td>This method returns detailed information about managed endpoints.</td><td>get_managed_endpoints_details <br/>Security</td></tr>
<tr><td>Move Endpoints</td><td>This method moves a list of endpoints to a custom group.</td><td>move_endpoints <br/>Security</td></tr>
<tr><td>Set Endpoint Label</td><td>This method sets a new label to an endpoint.</td><td>set_endpoint_label <br/>Security</td></tr>
<tr><td>Create Scan Task</td><td>This method creates a new scan task.</td><td>create_scan_task <br/>Security</td></tr>
<tr><td>Create Scan Task By Mac Address</td><td>Use this method to generate a scan task for managed endpoints identified by their MAC address.</td><td>create_scan_task_by_mac <br/>Security</td></tr>
<tr><td>Get Scan Task List</td><td>This method returns the list of scan tasks.</td><td>get_scan_tasks_list <br/>Security</td></tr>
<tr><td>Get Scan Task Status</td><td>This method retrieves information about the status of a given task identified using its ID.</td><td>get_scan_tasks_status <br/>Security</td></tr>
<tr><td>Create Add File To Quarantine Task</td><td>This method creates a new task to add a file to quarantine.</td><td>create_add_file_to_quarantine_task <br/>Security</td></tr>
</tbody></table>

### operation: Get Computers Quarantine List
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Endpoint ID</td><td>The ID of the computer for which you want to retrieve the quarantined items.
</td></tr><tr><td>Page</td><td>Specify the result page number. The default value is 1.
</td></tr><tr><td>Per Page</td><td>Specify the number of items to fetch in a page.
</td></tr><tr><td>Filter</td><td>Specify the filters to be used when querying the quarantine items list.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "id": "",
    "jsonrpc": "",
    "result": {
        "total": "",
        "page": "",
        "perPage": "",
        "pagesCount": "",
        "items": [
            {
                "id": "",
                "quarantinedOn": "",
                "actionStatus": "",
                "companyId": "",
                "endpointId": "",
                "endpointName": "",
                "endpointIP": "",
                "canBeRestored": "",
                "canBeRemoved": "",
                "threatName": "",
                "details": {
                    "filePath": ""
                }
            }
        ]
    }
}</pre>
### operation: Get Exchange Quarantine List
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Endpoint ID</td><td>The ID of the computer for which you want to retrieve the quarantined items.
</td></tr><tr><td>Page</td><td>Specify the result page number. The default value is 1.
</td></tr><tr><td>Per Page</td><td>Specify the number of items to fetch in a page.
</td></tr><tr><td>Filter</td><td>Specify the filters to be used when querying the quarantine items list.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "id": "",
    "jsonrpc": "",
    "result": {
        "page": "",
        "pagesCount": "",
        "perPage": "",
        "total": "",
        "items": [
            {
                "id": "",
                "quarantinedOn": "",
                "actionStatus": "",
                "endpointId": "",
                "endpointName": "",
                "endpointIP": "",
                "endpointAvailable": "",
                "threatName": "",
                "companyId": "",
                "details": {
                    "threatStatus": "",
                    "itemType": "",
                    "detectionPoint": "",
                    "email": {
                        "senderIP": "",
                        "senderEmail": "",
                        "subject": "",
                        "recipients": [],
                        "realRecipients": []
                    }
                }
            }
        ]
    }
}</pre>
### operation: Get Accounts List
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Page</td><td>Specify the result page number. The default value is 1.
</td></tr><tr><td>Per Page</td><td>Specify the number of items to fetch in a page.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "id": "",
    "jsonrpc": "",
    "result": {
        "total": "",
        "page": "",
        "perPage": "",
        "pagesCount": "",
        "items": [
            {
                "id": "",
                "email": "",
                "profile": {
                    "fullName": "",
                    "language": "",
                    "timezone": "",
                    "landingPage": ""
                },
                "role": "",
                "rights": {
                    "companyManager": "",
                    "manageCompanies": "false",
                    "manageNetworks": "",
                    "manageInventory": "",
                    "managePoliciesRead": "",
                    "managePoliciesWrite": "",
                    "manageReports": "",
                    "manageUsers": "",
                    "manageRemoteShell": ""
                },
                "companyName": "",
                "companyId": ""
            }
        ]
    }
}</pre>
### operation: Get Policies List
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Page</td><td>Specify the result page number. The default value is 1.
</td></tr><tr><td>Per Page</td><td>Specify the number of items to fetch in a page.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "id": "",
    "jsonrpc": "",
    "result": {
        "total": "",
        "page": "",
        "perPage": "",
        "pagesCount": "",
        "items": [
            {
                "id": "",
                "name": "",
                "companyId": "",
                "companyName": ""
            }
        ]
    }
}</pre>
### operation: Add to Blocklist
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Type</td><td>Specify the type of item you want to block.
</td></tr><tr><td>Hash</td><td>The hash associated to the file you want to block.
</td></tr><tr><td>Source Info</td><td>Provide a description for this specific set of rule.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "jsonrpc": "",
    "method": "",
    "id": "",
    "params": {
        "companyId": "",
        "type": "",
        "rules": [
            {
                "note": "",
                "details": {
                    "algorithm": "",
                    "hash": ""
                }
            }
        ],
        "recursive": ""
    }
}</pre>
### operation: Get Block List Items
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Page</td><td>Specify the results page number.
</td></tr><tr><td>Per Page</td><td>Specify the number of items to fetch in a page.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "params": {
        "companyId": "",
        "page": "",
        "perPage": ""
    },
    "jsonrpc": "",
    "method": "",
    "id": ""
}</pre>
### operation: Remove from BlockList
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Hash Item ID</td><td>Specify the items you want to remove from the blocklist rule.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "params": {
        "ids": []
    },
    "jsonrpc": "",
    "method": "",
    "id": ""
}</pre>
### operation: Create Isolate Endpoint Task
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Endpoint ID</td><td>The ID of the endpoint to be isolated.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "id": "",
    "jsonrpc": "",
    "result": []
}</pre>
### operation: Create Restore Endpoint from Isolation
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Endpoint ID</td><td>The ID of the endpoint to be restored.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "id": "",
    "jsonrpc": "",
    "result": []
}</pre>
### operation: Get Custom Rules List
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Page</td><td>Specify the page number to retrieve.
</td></tr><tr><td>Per Page</td><td>Specify the number of items to fetch in a page.
</td></tr><tr><td>Company Id</td><td>Specify the company ID.
</td></tr><tr><td>Type</td><td>Specify the type of rules.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "id": "",
    "jsonrpc": "",
    "result": {
        "total": "",
        "page": "",
        "perPage": "",
        "pagesCount": "",
        "items": [
            {
                "id": "",
                "name": "",
                "ownerId": "",
                "description": "",
                "companyId": "",
                "status": "",
                "tags": [],
                "settings": {
                    "status": "",
                    "target": "",
                    "criteriaList": [
                        {
                            "field": "",
                            "relation": "",
                            "value": []
                        },
                        {
                            "field": "",
                            "relation": "",
                            "value": [],
                            "operator": ""
                        },
                        {
                            "field": "",
                            "relation": "",
                            "value": [],
                            "operator": ""
                        }
                    ],
                    "severity": ""
                }
            }
        ]
    }
}</pre>
### operation: Delete Custom Rule
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Rule Id</td><td>The ID of the rule to be deleted.
</td></tr><tr><td>Type</td><td>Specify the type of rule.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "id": "",
    "jsonrpc": "",
    "result": ""
}</pre>
### operation: Update Incident Note
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Incident Id</td><td>The ID of the incident to update.
</td></tr><tr><td>Type</td><td>The type of the target incident.
</td></tr><tr><td>Note</td><td>Specify the note to be added.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "id": "",
    "jsonrpc": "",
    "result": ""
}</pre>
### operation: Change Incident Status
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Incident Id</td><td>The ID of the incident to change status.
</td></tr><tr><td>Type</td><td>The type of the target incident.
</td></tr><tr><td>Status</td><td>The new status of the incident.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "id": "",
    "jsonrpc": "",
    "result": ""
}</pre>
### operation: Get Endpoints List
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Is Managed</td><td>Specify whether to list managed or unmanaged endpoints.
</td></tr><tr><td>Page</td><td>Specify the results page number.
</td></tr><tr><td>Per Page</td><td>Specify the number of items to fetch in a page.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "id": "",
    "jsonrpc": "",
    "result": ""
}</pre>
### operation: Get Managed Endpoints Details
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Endpoint ID</td><td>The ID of the endpoint for which the details will be returned.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "id": "",
    "jsonrpc": "",
    "result": {
        "id": "",
        "name": "",
        "companyId": "",
        "operatingSystem": "",
        "state": "",
        "ip": "",
        "lastSeen": "",
        "machineType": "",
        "agent": {
            "engineVersion": "7.",
            "primaryEngine": "",
            "fallbackEngine": "",
            "lastUpdate": "",
            "licensed": "",
            "productOutdated": "",
            "productUpdateDisabled": "",
            "productVersion": "",
            "signatureOutdated": "",
            "signatureUpdateDisabled": "",
            "type": ""
        },
        "group": {
            "id": "",
            "name": ""
        },
        "malwareStatus": {
            "detection": "",
            "infected": ""
        },
        "modules": {
            "advancedThreatControl": "",
            "antimalware": "",
            "contentControl": "",
            "deviceControl": "",
            "firewall": "",
            "powerUser": "",
            "networkAttackDefense": "",
            "integrityMonitoring": ""
        },
        "policy": {
            "id": "",
            "applied": "",
            "name": ""
        },
        "label": "",
        "moveState": "",
        "riskScore": {
            "value": "",
            "impact": "",
            "misconfigurations": "",
            "appVulnerabilities": "",
            "humanRisks": ""
        },
        "lastSuccessfulScan": {
            "name": "",
            "date": ""
        }
    }
}</pre>
### operation: Move Endpoints
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Endpoint ID</td><td>The ID of the endpoint to move.
</td></tr><tr><td>Group ID</td><td>The ID of the destination group.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "id": "",
    "jsonrpc": "",
    "result": ""
}</pre>
### operation: Set Endpoint Label
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Endpoint ID</td><td>The ID of the endpoint.
</td></tr><tr><td>Label</td><td>A string representing the label.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "id": "",
    "jsonrpc": "",
    "result": ""
}</pre>
### operation: Create Scan Task
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Target IDs</td><td>A list with the IDs of the targets to scan.
</td></tr><tr><td>Type</td><td>The type of scan.
</td></tr><tr><td>Scan Name</td><td>The name of the task.
</td></tr><tr><td>Return All TaskIds</td><td>Indicates if the response will contain the IDs for all the tasks created.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "id": "",
    "jsonrpc": "",
    "result": []
}</pre>
### operation: Create Scan Task By Mac Address
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Mac Addresses</td><td>The list of mac addresses of the endpoints to be scanned.
</td></tr><tr><td>Type</td><td>The type of scan.
</td></tr><tr><td>Scan Name</td><td>The name of the task.
</td></tr><tr><td>Return All TaskIds</td><td>Indicates if the response will contain the IDs for all the tasks created.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "id": "",
    "jsonrpc": "",
    "result": []
}</pre>
### operation: Get Scan Task List
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Status</td><td>The status of the task.
</td></tr><tr><td>Page</td><td>Specify the results page number.
</td></tr><tr><td>Per Page</td><td>Specify the number of items to fetch in a page.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "id": "",
    "jsonrpc": "",
    "result": {
        "page": "",
        "pagesCount": "",
        "perPage": "",
        "total": "",
        "items": []
    }
}</pre>
### operation: Get Scan Task Status
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Task ID</td><td>The ID of the task you want to retrieve the status of.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "id": "",
    "jsonrpc": "",
    "result": {
        "page": "",
        "pagesCount": "",
        "perPage": "",
        "total": "",
        "items": []
    }
}</pre>
### operation: Create Add File To Quarantine Task
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Endpoint ID</td><td>A list with the IDs of target endpoints.
</td></tr><tr><td>File Path</td><td>The absolute file path on disk.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "id": "",
    "jsonrpc": "",
    "result": []
}</pre>
## Included playbooks
The `Sample - bitdefender - 1.0.0` playbook collection comes bundled with the Bitdefender connector. These playbooks contain steps using which you can perform all supported actions. You can see bundled playbooks in the **Automation** > **Playbooks** section in FortiSOAR&trade; after importing the Bitdefender connector.

- Get Computers Quarantine List
- Get Exchange Quarantine List
- Get Accounts List
- Get Policies List
- Add to Blocklist
- Get Block List Items
- Remove from BlockList
- Create Isolate Endpoint Task
- Create Restore Endpoint from Isolation
- Get Custom Rules List
- Delete Custom Rule
- Update Incident Note
- Change Incident Status
- Get Endpoints List
- Get Managed Endpoints Details
- Move Endpoints
- Set Endpoint Label
- Create Scan Task
- Create Scan Task By Mac Address
- Get Scan Task List
- Get Scan Task Status
- Create Add File To Quarantine Task

**Note**: If you are planning to use any of the sample playbooks in your environment, ensure that you clone those playbooks and move them to a different collection since the sample playbook collection gets deleted during connector upgrade and delete.
