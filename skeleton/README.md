## Description
Skeleton REST API engine

Add this in *PatrowlManager* :

```
systemctl restart supervisord.service
```


```var/data/engines.Engine.json
}, {
  "model": "engines.engine",
  "pk": 14,
  "fields": {
    "name": "SKELETON",
    "description": "Skeleton",
    "allowed_asset_types": "[u'ip', u'fqdn', u'domain']",
    "created_at": "2019-03-27T12:38:50.794Z",
    "updated_at": "2019-03-27T12:38:50.794Z"
  }
```

```
python manage.py loaddata var/data/engines.Engine.json
```

````var/data/engines.EnginePolicy.json
  {
    "model": "engines.enginepolicy",
    "pk": 29,
    "fields": {
      "engine": 14,
      "owner": 1,
      "name": "Skeleton policy",
      "default": false,
      "description": "Skeleton policy",
      "options": "{\"max_timeout\":3600,\"xxxxx\":true}",
      "file": "",
      "status": "",
      "is_default": false,
      "created_at": "2019-01-11T14:09:27.933",
      "updated_at": "2019-01-11T14:09:27.944",
      "scopes": [
        6
      ]
    }
  }
```

```
python manage.py loaddata var/data/engines.EnginePolicy.json
```


## Dependancies
- Python 3 + pip
- See requirements.txt for others python packages (use "pip install -r requirements.txt")

## Testing URLs
