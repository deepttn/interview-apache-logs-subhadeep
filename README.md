# Overview

Create a tool to read a web server log file with the [Combined Log Format](http://fileformats.archiveteam.org/wiki/Combined_Log_Format), and output statistics based on the data. The input log files look something like this:

`216.144.240.130 - - [19/May/2019:03:42:51 +0000] "HEAD /robots.txt HTTP/1.1" 404 208 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36"` 

`169.248.212.254 - - [19/May/2019:03:35:17 +0000] "GET /image.jpg HTTP/1.1" 200 14327 "http://mail.google.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246 Mozilla/5.0"` 

The tool should be able to open a user defined log file, and print to the console the stats. In the event a line in the file can not be parsed, the line should be ignored, and all other lines used for the statistics output. The important information which should be displayed is:

- Total number of requests
- Total data transmitted over all requests
- Most requested resource
  - total number of requests for this resource
  - percentage of requests for this resource
- Remote host with the most requests
  - total number of requests from this remote host
  - percentage of requests for this resource
- Percentages of each class of HTTP status code (1xx, 2xx, 3xx, 4xx, 5xx)

## Example files

Within the `example` directory are some sample log files which were generated with the `generate-logs.py` script located in the `scripts` directory. Along with the sample log files are the output of statistics based on those log files. Refer to these outputs to ensure the statistics you are parsing are correct.

Additionally, in the `example` directory are real world log files, which are from the [Elasticsearch Example repo](https://github.com/elastic/examples/tree/master/Common%20Data%20Formats/apache_logs). 

### Generate Logs

In order to generate your own logs, run `scripts/generate-logs.py`. The usage

    ./generate-logs.py [-h] -f FILE [-v] [--aggressive]

`-f FILE` : Location of the log file to write to

`-v` : Enables verbose output (optional)

`--aggressive`: Speeds up log generation by 10x (optional)

`-h` : Displays the help message for arguments (optional)

## Cloning this Repo

Please **do not fork** this repo on Github, and instead create a fresh repo that is not linked to this one. The proper steps to do this can be found here.

1. Create a [new repo on Github](https://github.com/new) (or preferred git hosting service)

2. Clone this repo

   `git clone git@github.com:criticalmedia/interview-apache-logs.git`

   `cd interview-apache-logs`

3. Remove the `.git` directory
   `rm -rf .git`

4. Initialize a fresh repo
   `git init .`

5. Add your own remote to the repo
   `git remote add origin <github remote URL>`

6. Remove this README file and replace with details for running the script that outputs statistics.
   `rm -f README.md`