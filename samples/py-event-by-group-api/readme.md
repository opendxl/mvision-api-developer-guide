### Python events by system tree groups
This code demonstrates the following
 * retrieve threat events from MVISION epo for a given time window , and for a given group name

Prerequisites
 * Must register to McAfee developerhub
 * Must have access to MVISION API
 * Must have API key 
 * Must have client credentials to enable token generation 

Note:
Normally, v2 apis are the preferred way to go , as they follow the api standards. However, for specific use cases, for example, when the number of groups is to large, and the desired response / data is very specific, it is useful to use a combination for v1 and v2 apis

In this example, we wish to find all events that belong to nodes under a given system tree group. The steps are simple:
 * Get system tree group by name : groups api, filter by name 
 * Get the nodepath for the group : groups api for specific id group, extract nodepath
 * Get threat events where the nodepath attribute matches the one we want. events api. Since events have a large number of attributes, filter by nodepath is not currently supported. One workaround is to fetch all the events but then filter it application side. This is what I show in this example
