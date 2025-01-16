[comment]: # "Auto-generated SOAR connector documentation"
# Fresh Service

Publisher: Splunk Community  
Connector Version: 1.1.0  
Product Vendor: Freshworks
Product Name: Freshservice
Product Version Supported (regex): ".\*"  
Minimum Product Version: 6.1.1  

Fresh Service ITSM integration app.

[comment]: # " File: README.md"
[comment]: # " Copyright (c) 2024 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
### Freshservice

This app is designed to be used with the Freshservice API. Documentation for this API can be found [here](https://api.freshservice.com/#intro)

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Context asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**api_key** |  required  | password | API Token to authenticate with
**base_url** |  required  | string | URL to connect to

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[update ticket](#action-update-ticket) - Update ticket.
[add note](#action-add-note) - Add a note to a ticket.
[get ticket](#action-get-ticket) - Get ticket information.
[create ticket](#action-create-ticket) - Create a ticket.

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'update ticket'
Update ticket (issue)

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**category** |  optional  | Category | string |   
**ticket_id** |  required  | Ticket ID | string |  `freshservice ticket_id`
**responder_id** |  optional  | Agent/Responder | string |  
**sub_category** |  optional  | Sub-Category | string |  
**item_category** |  optional  | Item | string |  
**update_status** |  required  | Update Status by its numeric value | string |  
**update_priority** |  optional  | Update Priority by its numeric value | string |  
**bypass_mandatory** |  optional  | Mark true if required, need to be FS admin | string |  
**update_custom_field** |  optional  | Custome field name to be updated | string |  
**update_custom_field_value** |  optional  | Custom field value to be updated | string |  

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.ticket_id | string |  `freshservice ticket_id`  |  
action_result.parameter.udpate_status | numeric |  |  
action_result.parameter.update_priority | numeric |  |  
action_result.parameter.responder_id | numeric |  |  
action_result.parameter.category | string |  |  
action_result.parameter.sub_category | string |  |  
action_result.parameter.item_category | string |  |  
action_result.parameter.update_custom_field | string |  |  
action_result.parameter.update_custom_field_value | string |  |  
action_result.parameter.bypass_mandatory | string |  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 

## action: 'add note'
Add a note to a ticket.

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**body** |  required  | HTML format body | string |  
**private** |  optional  | Toggle for private note or not | boolean |   
**ticket_id** |  required  | Freshservice Ticket ID | numeric |  `freshservice ticket_id`

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.ticket_id | numeric |  `freshservice ticket_id`  |  
action_result.parameter.body | string |  |  
action_result.parameter.private | boolean |  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 

## action: 'get ticket'
Get ticket (issue) information.

Type: **generic**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ticket_id** |  required  | Ticket ID | string |  

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.ticket_id | string |  `freshservice ticket_id`  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 

## action: 'create ticket'
Create a ticket (issue).

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**status** |  required  | Status of ticket | numeric |  `incident status`
**subject** |  required  | Subject of the ticket | string |  `freshservice subject`
**group_id** |  required  | Group ID to assign ticket to | numeric |  `freshservice group_id`
**priority** |  required  | Priority of ticket (1-4) | numeric |  
**description** |  required  | Desciption of the ticket | string |  `freshservice description`
**requester_id** |  required  | ID of the requester | numeric |  `freshservice requester`

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.subject | string |  `freshservice subject`  |  
action_result.parameter.description | string | `freshservice description` |  
action_result.parameter.requester_id | numeric | `freshservice requester` |  
action_result.parameter.priority | numeric |  |  
action_result.parameter.status | numeric | `freshservice status` |  
action_result.parameter.group_id | numeric | `freshservice group_id` |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 

## Legal and License

This Phantom App is licensed under the Apache 2.0 license. Please see our [Contributing Guide](https://github.com/Splunk-SOAR-Apps/.github/blob/main/.github/CONTRIBUTING.md#legal-notice) for further details.
