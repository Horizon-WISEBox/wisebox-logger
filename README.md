# WISEBox Logger

A simple utility for logging of RFMON probe requests.

## Getting Started

### Dependencies

WISEBox Logger requires a Wi-Fi device that is in monitor mode. It has been
tested on Raspbian Linux but should run on most Linux variants and macOS (and
possibly Windows). Any version of Python 3.5 and up should be compatible. All
of the Python dependencies can be found in the [Pipfile](Pipfile). Usage of
[Pipenv](https://pypi.org/project/pipenv/) is recommended for setting up the
Python environment and installing dependencies.

### Installing

* Clone the repository
* Change the Python version in the Pipfile to your preferred version
* Install the dependencies with Pipenv

### Executing program

```
usage: wisebox-logger [-h] [--bucket.interval BUCKET.INTERVAL]
                      [--log.rollover.time LOG.ROLLOVER.TIME]
                      [--filters.rssi.min FILTERS.RSSI.MIN]
                      [--upload.enabled true|yes|false|no]
                      [--upload.url UPLOAD.URL]
                      [--upload.api_key UPLOAD.API_KEY]
                      [--upload.retry_interval UPLOAD.RETRY_INTERVAL]
                      [--upload.keep_logs true|yes|false|no]
                      [--inactivity.enabled true|yes|false|no]
                      [--inactivity.interval INACTIVITY.INTERVAL]
                      [--inactivity.action INACTIVITY.ACTION]
                      [--config CONFIG] [--version]
                      interface channel log.dir

802.11 probe request frame logger

positional arguments:
  interface             capture interface, e.g. wlan0
  channel               channel number to listen on
  log.dir               directory to write logs to

optional arguments:
  -h, --help            show this help message and exit
  ARG:   --bucket.interval BUCKET.INTERVAL
  NSKEY: bucket.interval
                        bucket interval time in minutes (default: 5)
  ARG:   --log.rollover.time LOG.ROLLOVER.TIME
  NSKEY: log.rollover.time
                        time, in minutes, between log file rollover (default:
                        60)
  ARG:   --filters.rssi.min FILTERS.RSSI.MIN
  NSKEY: filters.rssi.min
                        RSSI minimum filter level (default: None)
  ARG:   --upload.enabled true|yes|false|no
  NSKEY: upload.enabled
                        enable upload of logs (default: False)
  ARG:   --upload.url UPLOAD.URL
  NSKEY: upload.url
                        server url to upload logs to (default: None)
  ARG:   --upload.api_key UPLOAD.API_KEY
  NSKEY: upload.api_key
                        api key to use to authenticate with server (default:
                        None)
  ARG:   --upload.retry_interval UPLOAD.RETRY_INTERVAL
  NSKEY: upload.retry_interval
                        time, in minutes, to retry failed uploads (default:
                        10)
  ARG:   --upload.keep_logs true|yes|false|no
  NSKEY: upload.keep_logs
                        whether to keep uploaded logs or to delete after
                        upload (default: True)
  ARG:   --inactivity.enabled true|yes|false|no
  NSKEY: inactivity.enabled
                        whether to monitor for inactivity and take an action
                        (default: False)
  ARG:   --inactivity.interval INACTIVITY.INTERVAL
  NSKEY: inactivity.interval
                        inactivity time interval in minutes, after which
                        action is taken (default: 60)
  ARG:   --inactivity.action INACTIVITY.ACTION
  NSKEY: inactivity.action
                        action (command) to be taken after inactivity interval
                        elapsed (default: /bin/true)
  ARG:   --config CONFIG
  --version             show program's version number and exit
```

## Version History

* v1.3.0
  * Change from WISEParks to WISEBox
  * See [commit change](#2529daf29989fb3d160bf11c432b609b656e50ee)
* v1.2.0
  * Implented watchdog functionality to execute an action after a period
    of inactivity
  * See [commit change](d387093)
* v1.1.0
  * Added logfile upload to server functionality
  * See [commit change](a01dcbf)
* v1.0.1
  * Unkown values allowed in configuration files
  * See [commit change](aee3175)
* v1.0.0
  * Initial Release
  * Added logfile versioning
  * See [commit change](843c958)

## License

This project is licensed under the GNU AFFERO General Public License, Version 3
\- see the [LICENSE](LICENSE) file for details
