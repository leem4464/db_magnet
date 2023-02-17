# db_magnet
db_magnet is a code that verifies whether the database service is operating at a specific IP address.  It works based on the IP searches of criminalip, an OSINT search engine, and previously defined data. 

# Prerequisite
You need to receive an API key at https://www.criminalip.io in order to use db_magnet.

Since it is currently a beta service, all you have to do is to create a free beta account and find API key that is assigned to your account at https://www.criminalip.io/mypage/information


# Installation  

Clone repository:  

```  
$ git clone https://github.com/leem4464/db_magnet.git  
```

```  
$ cd project
```

```  
$ python3 -m venv .venv  
$ source .venv/bin/activate  
```

```  
$ pip3 install -r requirements.txt  
```

  

# Usage

```  
$ ./db_magnet.py --auth [your-criminalip-api-key]  
```

  

# Optional Arguments  

| Flag | MetaVar | Usage |
| -------------- | ----------- | ----------------------------------------------------- |
| `-A/--auth` | **API key** | api authentication with a valid criminalip.io api key |
| `-F/--file` | **File/Path** | Return information about IPs with a file |
| `-I/--ip` | **IP** | Return information about the IP |
| `-P/--port` | **Port Numbers** | Scan ports you input |
| `-O/--output` | **File Path** | Write return data to a log file |
| `-R/--read` | **File Path** | Read output log data |
| `-D/--domain` | **Domain** | Return whois info about the domain |


# Issue / Feedback
Thank you for using db_magnet. 

If you have any issues/feedback you want to tell me, please feel free to leave a comment or pop me an email.
