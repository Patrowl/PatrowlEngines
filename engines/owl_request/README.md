## Status
WIP - do not use in production environment

## Description
Curl REST API engine

Add this in *PatrowlManager* :

```
systemctl restart supervisord.service
```


```var/data/engines.Engine.json
}, {
  "model": "engines.engine",
  "fields": {
    "name": "OWL_REQUEST",
    "description": "Request engine",
    "allowed_asset_types": "[u'ip', u'fqdn', u'domain', u'url']",
    "created_at": "2019-03-27T12:38:50.794Z",
    "updated_at": "2019-03-27T12:38:50.794Z"
  }
```

```
python manage.py loaddata var/data/engines.Engine.json
```

## Dependancies
- Python 3 + pip
- See requirements.txt for others python packages (use "pip install -r requirements.txt")

## Testing URLs
