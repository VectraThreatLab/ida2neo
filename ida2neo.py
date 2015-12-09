'''
 _     _       ____
(_) __| | __ _|___ \ _ __   ___  ___
| |/ _` |/ _` | __) | '_ \ / _ \/ _ \
| | (_| | (_| |/ __/| | | |  __/ (_) |
|_|\__,_|\__,_|_____|_| |_|\___|\___/

vectra networks
http://www.vectranetworks.com
Export IDB callgraph to Neo4j for maximum query excellence
'''

import idaapi
import idautils
import json
import urllib2

'''
Cypher Queries

Regex match
	Match (n) where n.name =~ '.*memmove.*' RETURN n

Find one shortest path from _DriverEntry to _McGenControlCallbackV2
	MATCH (q:Function) WHERE q.name = '_DriverEntry_at_8'
	MATCH (r:Function) WHERE r.name = '_McGenControlCallbackV2_at_36'
	MATCH p = shortestPath((q)-[*..15]->(r))
	RETURN p

Find all shortest path from _DriverEntry to _McGenControlCallbackV2
	MATCH (q:Function) WHERE q.name = '_DriverEntry_at_8'
	MATCH (r:Function) WHERE r.name = '_McGenControlCallbackV2_at_36'
	MATCH p = allShortestPaths((q)-[*..15]->(r))
	RETURN p

Find callers of memset
	MATCH (n:Function)-[:CALLS]->(a:Function) WHERE a.name = '_memset'  RETURN n LIMIT 1000

Find Callers of Callers of memset
	MATCH (q:Function)-[:CALLS]->(n:Function)-[:CALLS]->(a:Function) WHERE a.name = '_memset'  RETURN q LIMIT 1000

Set bulletin of _DiskFdoQueryWmiRegInfoEx_at_16
	MATCH (n { name: '_DiskFdoQueryWmiRegInfoEx_at_16' }) SET n.bulletin = 'MS15-007' RETURN n

'''

URL = r'http://localhost:7474/db/data/transaction/commit'
STATEMENT = '{\"statements\":[%s]}'
SUB_STATEMENT = '{\"statement\":\"CREATE (p:Function {name:{name},bulletin:{bulletin},notes:{notes}}) RETURN p\",\"parameters\":{\"name\":\"%s\",\"bulletin\":\"%s\",\"notes\":\"%s\"}}'
SUB_STATEMENT2 = '{\"statement\":\"MATCH (a:Function {name:{name}}), (b:Function {name:{name2}}) CREATE (a)-[:CALLS {bulletin:{bull}}]->(b)\",\"parameters\":{\"name\":\"%s\",\"name2\":\"%s\",\"bull\":\"%s\"}}'
MAX_BATCH = 400


def MakeRestReq(sBatch, uCnt):
    req = urllib2.Request(URL, STATEMENT % (sBatch.rstrip(',')), {
                          'Content-Type': 'application/json'})
    f = urllib2.urlopen(req)
    response = f.read()
    print 'Iteration - [%d]' % (uCnt)
    f.close()

# Create dummy node
MakeRestReq(SUB_STATEMENT % ('indirect_call', 'BASE_IMPORT', 'BASE_IMPORT'), 0)

# Save Nodes
sBatch = ''
uCnt = 1
for _ in Functions():
    sFunctionName = GetFunctionName(_).replace(
        '@', '_at_').replace('?', '_qm_')
    sQuery = SUB_STATEMENT % (sFunctionName, 'BASE_IMPORT', 'BASE_IMPORT')

    if uCnt % MAX_BATCH == 0:
        MakeRestReq(sBatch, uCnt)
        sBatch = ''
    else:
        sBatch += sQuery + ','

    uCnt += 1

if sBatch != '':
    MakeRestReq(sBatch, uCnt)
    sBatch = ''

print '[i] Finished Node Import'

# Save Relations
sBatch = ''
uCnt = 1

# for each defined function
for z in Functions():
    # for each xref to that function
    for xref in XrefsTo(z):
        sCaller = GetFunctionName(xref.frm).replace(
            '@', '_at_').replace('?', '_qm_')
        sCallee = GetFunctionName(z).replace('@', '_at_').replace('?', '_qm_')
        if sCaller == '':
            sCaller = 'indirect_call'
        if sCallee == '':
            sCallee = 'indirect_call'
        sQuery = SUB_STATEMENT2 % (sCaller, sCallee, 'BASE_IMPORT')
        if uCnt % MAX_BATCH == 0:
            MakeRestReq(sBatch, uCnt)
            sBatch = ''
        else:
            sBatch += sQuery + ','
        uCnt += 1

if sBatch != '':
    MakeRestReq(sBatch, uCnt)
    sBatch = ''

print '[i] Finished Edge Import'
