## NPA AWS automation

This tool was built for a quick demo, it is **not designed for production**.

The tool will connect to an AWS instance (use the right accesskey) and collect information about the running EC2 instances with specific tags. 
For each instance with the right tags (_ztna_available_ and _publisher_) it will create a private app entry on the netskope tenant, associating it with the publisher.

~~~
usage: npa_aws_tool.py [-h] --regions REGIONS [REGIONS ...] --access-key ACCESS_KEY --secret-key SECRET_KEY
                       [--session-token SESSION_TOKEN] [--format {detailed,simple}] [--netskope-url NETSKOPE_URL]
                       [--netskope-token NETSKOPE_TOKEN] [--debug] [--add-to-netskope]
npa_aws_tool.py: error: the following arguments are required: --regions, --access-key, --secret-key
~~~
