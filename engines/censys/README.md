# Engine-CENSYS


## Variable

### this.scanner

Used to load the configuration.

The structure is :
```json
{
  "name": XXX,
  "version": XXX,
  "keys": [
  {
    "uid": XXX,
    "secret": XXX
  },
  XXX
  ]
}```

### this.scans
Used to store all related to the scans

The structure is :
```json
{
  "XXX": {
    "assets": {
      "XXX": {
        "begin": XXX,
        "left": XXX
      }
    },
    "issues": [
      XXX
    ],
    "options": {
      XXX
    },
    "started_at": XXX,
    "status": XXX,
    "summary": {
      "engine_name": XXX,
      "engine_version": XXX,
      "nb_high": XXX,
      "nb_info": XXX,
      "nb_issues": XXX,
      "nb_low": XXX,
      "nb_medium": XXX,
      "nb_scan": XXX
    },
    "totalLeft": XXX,
    "unreachable_host": [
      XXX
    ],
    "up_cert": {
      XXX
    }
  }
}```

### this.stoped
The list of scan stopped used between the moment of the scan has been stop and the moment of finishing cleaning the query queue, this guaranties that the query demon stop using queries of a stopped scan

### this.queries
The list used as FIFO to stock the query to censys api
The structure of a query is :

 ```json
 {"search": [assets, XXX],"scan_id": XXX}```
 or
```json
{"view": XXX,"scan_id":XXX,"assets": XXX}```



### this.certificates
The list of instance of censys client api, initialysed with different user and keys.
Usefull to multithread the queries to censys api

### revoke
The dict of already loaded control distribution list with their containing certificates

### this.keys
The list of `{"uid":XXX, "key":XXX}` used to initiate the connection to censys api

### this.requestor
The list of demon thread, picking queries in this.queries to request the censys api


## Function

### _loadconfig

Load censys config file and start the queries thread demon, from the file censys.json located in BASE_DIR

###reloadconfig

Call _loadconfig to reload the configuration

### start_scan

First check the api call options
Then load the options and prepare the structure of the scans
Finally add the search queries corresponding to options.assets given

Parameter :
  Post parameter of starting scan :
  ```json
    {
      "assets": [],
      "options" : {
          "do_scan_valid": XXX,
          "ignore_changed_certificate": XXX,
          "changed_certificate_port_test": [XXX],
          "do_scan_trusted": XXX,
          "verbose": XXX,
          "do_scan_ca_trusted": XXX,
          "do_scan_self_signed": XXX,
          "assets": [XXX],
          "trusted_host":
              [
                XXX
              ]
      },
      "scan_id": XXX
  }```

### _put_queries
  Just add a new query at the start of the fifo this.queries

  Parameter :
  - dict : the structure to insert in the queries fifo

### _remove_scan
  function used to filter the queries fifo (removes queries of the stopped scan), when removing a scan

  return False if is in scans stopped (this.stopped), else True

  Parameter :
  - a query structure

### stop_scan
  Check if the scan can be stopped then stop it by filtering queries fifo and changing his status

  Parameter :
  - string : the id of the scan to stop

### clean

  Clean all scan STOPPED or FINISHED

### clean_scan
  Check if the scan can be clean then remove all data related to the scan results and issues

  Parameter :
  - string : the id of the scan to clean

### getreport
  Check for data about a passed scan saved in the results folder

  Parameter :
  - string : the id of the scan to get the report saved

### scan_status
  return the formated status of a scan
  It can be "WAITING TO START","SCANNING","STOPPED","FINISHED"

  Parameter :
  - string : the id of the scan to get the status

### status
  return the formated status of scans
  It can be "WAITING TO START","SCANNING","STOPPED","FINISHED"

### info
  return the configuration

### getfindings
  return the formated result of a scan

  result structure :
  ```json
  {"scan_id": XXX, "status": XXX,"detail": "XXX certificates to proceed"}```

  Parameter :
  - string : the id of the scan to get the status

### _create_issues_no_verbose
Build the issues for getfindings when the "verbose" is set to True

### _json_serial
  function used to formating to json a date object when formating the result of scans

  Parameter:
  - the object to format

### _requestor_d
  The thread demon, it does :
  - picking queries in queries fifo
  - request censys api
  - analyses and then build issues

  Parameter:
  - int : the id of the censys key to be used by the thread

### _search_cert
  The function to queries censys api when we're doing a search query on censys api
  - first query the censys api to get the list of related certificates
  - then add view queries to queries FIFO referring to the list of certificate

  Parameters:
  - string : the asset to search in censys
  - string : the id of the scan
  - int : the id of censys key to use to query censys api

### _get_view_cert
  The function to queries censys api when we're doing a view query on censys api

  Just query censys api for a certificate with the view endpoint

  Parameter :
  - string : the signature of the certificate to search on censys
  - int : the id of censys key to use to query censys api

### _ignore_changed_certificate
  Return true or false depending on if we need to ignore the certificate

  call to _still_exist to know if the certificate is the current one on host.

  Their is 3 case :
  - the server certificate is unreachable, we don't ignore
  - the server certificate has been recover :
    - the one we test is the same, we don't ignore
    - the one we test is one of the old server certificate, we ignore it

  Parameters:
  - the view of the certificate
  - string : the scan id

### _view_valid
  function testing the validity of a certificate, date + revocation and build corresponding issues

  - check validity date
  - get control distribution point certificate list
  - check if not in it

  Parameters:
  - the view of the certificate
  - string : the certificate signature
  - string : the scan id
  - string :  the asset of the current search

### _still_exist
  Return if the certificate view passed if the current on the host url parameter.
  - return True if the certificate on the host if the one on the host
  - return False if the certificate is not the same of the host
  - exception when the ssl certificate can't be retrieve

  Parameters :
  - string : the url where to find the certificates
  - sting : the serial of the certificate compared of the certificate of the url host
  - array int : the list of port to search for a ssl certificate
  - string : the scan id

### _view_trusted
  Get all the alternative name of a certificate and verify if they are in the list of trusted host
  If the host is not in the trusted host list create an issue corresponding.

  Parameters:
  - the view of the certificate
  - string : the scan id
  - string : the asset of the current search

### _is_self_signed
  Create issues for self signed certificate

  Parameters:
  - the view of the certificate
  - string : the scan id
  - string :  the asset of the current search


### _ca_trusted
  Create issues for non trusted AC

  Parameters:
  - the view of the certificate
  - string : the scan id
  - string :  the asset of the current search
  - int : the id of censys key to use to query censys api
