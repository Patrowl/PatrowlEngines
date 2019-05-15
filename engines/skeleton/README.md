## Description
Skeleton REST API engine

Add this in *PatrowlManager* :

```var/etc/supervisord-celery0.conf
program:celery-skeleton]
command=celery worker --hostname=skeleton-node@%%n --app=app -l info -Q scan-skeleton,monitor-skeleton --purge --without-mingle --without-gossip -Ofair
stdout_logfile=var/log/celeryd.skeleton.log
stderr_logfile=var/log/celeryderr.skeleton.log
autostart=true
autorestart=true
startsecs=5
stopwaitsecs=60
killasgroup=true
priority=990
```

```
systemctl restart supervisord.service
```


```assets/models.py
    {
        "name": "Skeleton",
        "datatypes": ["fqdn","ip","domain"]
    },
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
      "options": "{\"max_timeout\":3600,\"search_github\":true}",
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
- Python 2.7 + pip
- See requirements.txt for others python packages (use "pip install -r requirements.txt")

## Testing URLs
