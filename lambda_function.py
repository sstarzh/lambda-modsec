import boto3
import json
import urllib
from boto3.dynamodb.conditions import Key
# Mod Sec
from ModSecurity import *
print('Loading function')

dynamo = boto3.resource('dynamodb')


def respond(err, res=None):
    return {
        'statusCode': '403' if err else '200',
        'body': json.dumps(res),
        'headers': {
            'Content-Type': 'application/json',
        },
    }


def lambda_handler(event, context):
    print('Event:' + json.dumps(event))
#ModSec
    modsec = ModSecurity()
    rules = Rules()
    rules.loadFromUri("/opt/lib/modsec.conf")
    ret = rules.getParserError()
    if ret:
        print('Unable to parse rule: %s' % ret)
    
    transaction = Transaction(modsec, rules, None)
    requestContext = event['requestContext']
    path = event['path']
    headers = event['headers']
    host = headers['Host']
    print('Host:' + host)
    operation = event['httpMethod']
    if operation is not 'GET':
        body = event['body']
    qs = event["queryStringParameters"]
    queryString = ''
    if qs is not None:
        for query in qs:
            print(query + '=' + qs[query])
            if qs[query] != "":
                queryString = queryString + query + '=' + qs[query] + '&'
            else:
                queryString = queryString + query + '&'
        queryString = '?' + queryString[:-1]
        print('queryString:' + queryString)
 #   print('qs:' + json.dumps(qs))
 #   domain = requestContext['domainName']
    protocol = requestContext['protocol'][5:]
    uri = 'https://' + host + path + queryString
    print('URI' + uri)
 #   contentType = headers['Content-Type']
    # Process URI
    transaction.processURI(uri, operation, protocol)
    # Process headers
 #   if contentType is not None:
    transaction.processRequestHeaders()
 #   if body is not None:
    transaction.processRequestBody()
    intervention = ModSecurityIntervention()
    if transaction.intervention(intervention):
        print('ModSec BLOCKED')
        return respond(ValueError, 'Blocked by Modsec')
    else:
        print('ModSec PASSED')
    tab = dynamo.Table('modsec')
 
    operations = {
        'DELETE': lambda dynamo, x: tab.delete_item(),
        'GET': lambda dynamo, x: tab.scan(),
        'POST': lambda dynamo, x: tab.put_item(),
        'PUT': lambda dynamo, x: tab.update_item(),
    }

    if operation in operations:
        payload = 'modsec' if operation == 'GET' else json.loads(event['body'])
        return respond(None, operations[operation](tab, payload))
    else:
        return respond(ValueError, 'Unsupported method "{}"'.format(operation))
