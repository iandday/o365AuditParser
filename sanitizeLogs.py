#! /usr/bin/env python3

'''o365 Audit Log Sanitizer

Redact sensitive fields from Office365 Audit logs

Author: Ian Day
Initial Release: December 8 2019 Version 1.0
'''

import csv
import json

# customize to fit your environment
fileName = 'AuditLog_2019-11-25_2019-12-03.csv'
redactedStr='*REDACTED*'
redactedFields = [ 
    'LogonUserSid',
    'Query',
    'ModifiedProperties',
    'ActorIpAddress',
    'MailboxOwnerUPN',
    'ListId',
    'DestinationFileName',
    'Item',
    'SessionId',
    'WebId',
    'MachineId',
    'Parameters',
    'ApplicationId',
    'ExchangeLocations',
    'CorrelationId',
    'UserKey',
    'ClientVersion',
    'TargetUserOrGroupName',
    'ObjectId',
    'Id',
    'SourceRelativeUrl',
    'ActorContextId',
    'DestFolder',
    'OriginatingServer',
    'SiteUrl',
    'MailboxGuid',
    'ClientIP',
    'IntraSystemId',
    'Target',
    'ExtendedProperties',
    'Actor',
    'MachineDomainInfo',
    'UserAgent',
    'ClientIPAddress',
    'UniqueSharingId',
    'OrganizationId',
    'DestinationRelativeUrl',
    'MailboxOwnerSid',
    'UserId',
    'ListItemUniqueId',
    'MailboxOwnerMasterAccountSid',
    'InterSystemsId',
    'SourceFileName',
    'OrganizationName',
    'AffectedItems',
    'EffectiveOrganization',
    'ClientInfoString',
    'TargetContextId',
    'EventData',
    'ClientApplication',
    'Site',
    'Folder'
]

# required for output file
cleanOutput = []
auditFieldNames = ['CreationDate','UserIds','Operations','AuditData']


with open(fileName, 'r', encoding='latin-1') as inFile:
    dictReader = csv.DictReader(inFile, fieldnames=auditFieldNames)
    for line in dictReader:
        try:
            # most data is contained in a large json string
            # create dicitonary and loop through fields
            record = json.loads(line['AuditData'])
            for field in record:
                if field in redactedFields:
                    record[field] = redactedStr
            # update current log entry with redacted fields
            line['AuditData'] = json.dumps(record)
            line['UserIds'] = redactedStr
            # add to output variable
            cleanOutput.append(line)
        except:
            continue

# write to file
with open('redacted' + fileName, 'w') as outFile:
    outWriter = csv.DictWriter(outFile, fieldnames=auditFieldNames, lineterminator='\n')
    outWriter.writeheader()
    outWriter.writerows(cleanOutput)

